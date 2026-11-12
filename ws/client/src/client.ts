/**
 * The WebSocket client: dial a tightbeam server, emit frames on multiplexed
 * streams, and serve the streams the server opens.
 */

import type {
	CleartextConnectOptions,
	ConnectOptions,
	GoAwayReason,
	MutualConnectOptions,
	DuplexServeHandler,
	MutualIdentity,
	MuxDuplexStream,
	MuxRequestStream,
	MuxWsClient,
	ServeClaim,
	SocketCloseInfo,
	StreamingServeHandler,
	StreamRoute,
	TransitRefusal,
	UnaryServeHandler,
} from "#wasm";
import type { Engine, EngineParts } from "./engine.js";
import { ChunkSource } from "./chunks.js";
import { ClientTransportError } from "./errors.js";
import { Frame } from "./frame.js";
import { PushHalf } from "./push.js";
import { ServedStream } from "./served.js";

export type { CleartextConnectOptions, ConnectOptions, MutualConnectOptions, StreamRoute } from "#wasm";

/**
 * The WebSocket CLOSED readyState, reported once the client has released
 * its socket.
 */
const WEBSOCKET_CLOSED = 3;

/**
 * The client state a reader sees: live from the socket, or frozen when the
 * client released it.
 */
interface ClientView {
	readonly readyState: number;
	readonly maxConcurrentStreams: number;
	readonly hasStreamHeadroom: boolean;
	readonly hasPendingStreams: boolean;
	readonly goawayReason: GoAwayReason | undefined;
	readonly goawayCode: number | undefined;
	readonly usableSendBudget: number | undefined;
	readonly sessionReceiptDer: Uint8Array | undefined;
}

/**
 * Where a client's socket stands: live, or released with the view it had.
 */
type SocketState =
	| { readonly phase: "live"; readonly socket: MuxWsClient }
	| { readonly phase: "released"; readonly view: ClientView };

/**
 * The lifecycle of one wasm socket: observation and idempotent release.
 * {@link release} hands the wasm object to its consuming close, so a released
 * state holds the snapshot taken at release alone, and every member reads
 * that snapshot.
 */
class SocketLifecycle {
	private state: SocketState;

	/**
	 * Captured at construction so closure stays observable after
	 * {@link release} frees the wasm object.
	 */
	readonly closed: Promise<SocketCloseInfo>;

	constructor(socket: MuxWsClient) {
		this.state = { phase: "live", socket };
		this.closed = socket.closed;
	}

	/**
	 * The state a reader sees: the live socket, or the snapshot release
	 * took.
	 */
	view(): ClientView {
		if (this.state.phase === "live") {
			return this.state.socket;
		}

		return this.state.view;
	}

	/**
	 * The socket, for a member that calls into the wasm object.
	 *
	 * @throws A `ConnectionClosed` transport error after {@link release}.
	 */
	socket(operation: string): MuxWsClient {
		if (this.state.phase === "released") {
			throw ClientTransportError.closed(operation);
		}

		return this.state.socket;
	}

	/**
	 * Snapshot the view, then close the socket through the close that
	 * consumes its wasm object. Idempotent.
	 */
	release(): void {
		if (this.state.phase === "released") {
			return;
		}

		const socket = this.state.socket;
		const view: ClientView = {
			readyState: WEBSOCKET_CLOSED,
			maxConcurrentStreams: socket.maxConcurrentStreams,
			hasStreamHeadroom: false,
			hasPendingStreams: false,
			goawayReason: socket.goawayReason,
			goawayCode: socket.goawayCode,
			usableSendBudget: socket.usableSendBudget,
			sessionReceiptDer: socket.sessionReceiptDer,
		};

		this.state = { phase: "released", view };
		socket.close();
	}
}

/**
 * Options accepted by {@link TightbeamWsClient.emit}.
 */
export interface EmitOptions {
	/**
	 * Abort the emit: the stream is cancelled (best-effort MuxCancel to
	 * the peer, cap slot freed) and the promise rejects with the signal's
	 * abort reason. Timeouts compose as `AbortSignal.timeout(ms)`.
	 */
	signal?: AbortSignal;
}

/**
 * Options accepted by the waiting surfaces ({@link TightbeamWsClient.ping},
 * {@link TightbeamWsClient.waitForStreamSlot}).
 */
export interface WaitOptions {
	/**
	 * Give up waiting: the promise rejects with the signal's abort
	 * reason. The connection is untouched. Deadlines compose as
	 * `AbortSignal.timeout(ms)`.
	 */
	signal?: AbortSignal;
}

/**
 * Answers one server-initiated stream: receives the decoded request frame
 * and returns the response frame, or `undefined`/`null` for a bodiless
 * acceptance.
 */
export type MuxStreamHandler = (frame: Frame) => Promise<Frame | undefined | null> | Frame | undefined | null;

/**
 * A progressive body. Each yield is one chunk as the peer sent it, and the
 * iteration ends after the peer's `last` chunk. The body owns its wasm handle
 * and frees it on every exit, and every loop over it shares the one body, as
 * the progressive bodies section of `docs/ws-client.md` describes.
 */
export interface StreamBody extends AsyncIterable<Uint8Array> {
	/**
	 * End the body and free its handle, which discards the chunks still to
	 * come. A later iteration yields nothing.
	 */
	[Symbol.asyncDispose](): Promise<void>;
}

/**
 * Answers a progressive request body with a reassembled Frame (or
 * bodiless acceptance). `route` carries the Open's target and hop budget.
 *
 * The client frees the body once the handler settles.
 */
export type StreamingBodyHandler = (
	body: StreamBody,
	route: StreamRoute,
) => Promise<Frame | undefined | null> | Frame | undefined | null;

/**
 * Reply half for {@link TightbeamWsClient.serveDuplex}. Its pushes run in the
 * order they were made, and a push that waits holds a copy of its chunk.
 */
export interface ReplySink {
	/**
	 * Push one reply chunk toward the peer. An empty chunk sends nothing.
	 *
	 * @throws TightbeamTransportError `StreamClosed` once the reply half is
	 * released.
	 */
	push(chunk: Uint8Array): Promise<void>;
	/**
	 * Release the reply half before the handler settles. The status the
	 * handler settles with still ends the stream.
	 */
	[Symbol.asyncDispose](): Promise<void>;
}

/**
 * Full-duplex body handler: consume request chunks and push reply chunks.
 * Resolve with the status that refuses the stream, or `undefined` for `Ok`.
 * `route` carries the Open's target and hop budget.
 *
 * The client frees the body and the reply half once the handler settles.
 */
export type DuplexBodyHandler = (
	body: StreamBody,
	reply: ReplySink,
	route: StreamRoute,
) => Promise<TransitRefusal | void> | TransitRefusal | void;

/**
 * Client-initiated progressive request: push chunks, then close for the
 * `Frame` response. The calls on the stream run in the order they were made,
 * and a close consumes the handle. Bind the stream with `await using`, so a
 * throw or a `break` cancels it.
 */
export interface RequestStream {
	/**
	 * Push one request chunk. An empty chunk sends nothing.
	 *
	 * @throws TightbeamTransportError `StreamClosed` after a close or a
	 * disposal.
	 */
	push(chunk: Uint8Array): Promise<void>;
	/**
	 * Finish the request body and resolve with the response Frame, or
	 * `undefined` when the peer answered without a body.
	 *
	 * @throws TightbeamTransportError `StreamClosed` after an earlier close
	 * or a disposal.
	 */
	close(): Promise<Frame | undefined>;
	/**
	 * Push the final request chunk with `last` set, then resolve with the
	 * response Frame (or `undefined`).
	 *
	 * @throws TightbeamTransportError as {@link close} does.
	 */
	closeWith(chunk: Uint8Array): Promise<Frame | undefined>;
	/**
	 * Cancel a stream that no close reached, and free its handle. A closed
	 * stream is already released, so its disposal leaves the close to
	 * settle.
	 */
	[Symbol.asyncDispose](): Promise<void>;
}

/**
 * Client-initiated duplex stream. Pushes reach the socket eagerly, so a
 * chunk-for-chunk conversation is sound. The request half and the reply
 * {@link body} end apart, as `docs/ws-client.md` describes. Bind the stream
 * with `await using`, so a throw cancels it.
 */
export interface DuplexStream {
	/**
	 * Push one request chunk toward the peer.
	 *
	 * @throws TightbeamTransportError `StreamClosed` after a close or a
	 * disposal.
	 */
	push(chunk: Uint8Array): Promise<void>;
	/**
	 * Finish the request body without a final chunk payload.
	 *
	 * @throws TightbeamTransportError `StreamClosed` after an earlier close
	 * or a disposal.
	 */
	close(): Promise<void>;
	/**
	 * Push the final request chunk with `last` set and close the body.
	 *
	 * @throws TightbeamTransportError as {@link close} does.
	 */
	closeWith(chunk: Uint8Array): Promise<void>;
	/**
	 * Progressive reply body from the peer on this stream. A `break` out of
	 * it cancels the stream.
	 */
	readonly body: StreamBody;
	/**
	 * Release both halves: an open request half cancels the stream, and the
	 * body frees its handle.
	 */
	[Symbol.asyncDispose](): Promise<void>;
}

/**
 * Options accepted by {@link TightbeamWsClient.serve},
 * {@link TightbeamWsClient.serveStreaming}, and
 * {@link TightbeamWsClient.serveDuplex}.
 */
export interface ServeOptions {
	/**
	 * How the call claims the stream dispatch, `shared` by default. An
	 * `exclusive` claim suits one dispatch owner, such as the
	 * `SubscriptionManager`, and every later `serve*` call on this client
	 * throws `ServeDispatchClaimed`.
	 */
	readonly claim?: ServeClaim;
}

/**
 * The DER of a response frame, or `undefined` for a bodiless answer.
 */
type ResponseDer = Uint8Array | undefined;

/**
 * A client-initiated progressive request over its wasm stream, which decodes
 * the response frame. Its {@link PushHalf} orders its calls and releases
 * the stream.
 */
class WasmRequest implements RequestStream {
	readonly #half: PushHalf<MuxRequestStream>;

	readonly #parts: EngineParts;

	constructor(parts: EngineParts, stream: MuxRequestStream) {
		this.#parts = parts;
		this.#half = new PushHalf(stream);
	}

	push(chunk: Uint8Array): Promise<void> {
		const pushed = this.#half.push(chunk);
		return pushed;
	}

	async close(): Promise<Frame | undefined> {
		const closing = (stream: MuxRequestStream): Promise<ResponseDer> => stream.close();
		const der = await this.#half.close("close", closing);

		const response = Frame.response(this.#parts, der);
		return response;
	}

	async closeWith(chunk: Uint8Array): Promise<Frame | undefined> {
		const closing = (stream: MuxRequestStream, last: Uint8Array): Promise<ResponseDer> => stream.closeWith(last);

		const der = await this.#half.closeWith(chunk, closing);
		const response = Frame.response(this.#parts, der);
		return response;
	}

	async [Symbol.asyncDispose](): Promise<void> {
		this.#half[Symbol.dispose]();
	}
}

/**
 * A client-initiated duplex stream over its wasm stream, whose reply body
 * reads through a handle of its own. Its {@link PushHalf} orders the calls
 * on the request half and releases it.
 */
class WasmDuplex implements DuplexStream {
	readonly body: StreamBody;

	readonly #half: PushHalf<MuxDuplexStream>;

	constructor(stream: MuxDuplexStream) {
		const body = stream.takeBody();
		this.body = new ChunkSource(body);
		this.#half = new PushHalf(stream);
	}

	push(chunk: Uint8Array): Promise<void> {
		const pushed = this.#half.push(chunk);
		return pushed;
	}

	async close(): Promise<void> {
		const closing = (stream: MuxDuplexStream): Promise<void> => stream.close();
		await this.#half.close("close", closing);
	}

	async closeWith(chunk: Uint8Array): Promise<void> {
		const closing = (stream: MuxDuplexStream, last: Uint8Array): Promise<void> => stream.closeWith(last);
		await this.#half.closeWith(chunk, closing);
	}

	/**
	 * Free the request half first, so an open stream cancels and a body read
	 * in flight settles, then free the body.
	 */
	async [Symbol.asyncDispose](): Promise<void> {
		this.#half[Symbol.dispose]();
		await this.body[Symbol.asyncDispose]();
	}
}

/**
 * A multiplexed tightbeam client over a single WebSocket session,
 * HPKE-encrypted (`Engine.connect`, `Engine.connectMutual`) or cleartext
 * (`Engine.connectCleartext`). A client lives until {@link close}, the peer's
 * close, or a GoAway, as the lifetime section of `docs/ws-client.md` states.
 */
export class TightbeamWsClient {
	/**
	 * The socket while live, and the view it had once released, so
	 * reconnect policies can still read GoAway facts from a released
	 * client.
	 */
	private readonly lifecycle: SocketLifecycle;

	/**
	 * The engine that dialed this client, which decodes every frame the
	 * client receives.
	 */
	readonly #parts: EngineParts;

	private constructor(parts: EngineParts, socket: MuxWsClient) {
		this.#parts = parts;
		this.lifecycle = new SocketLifecycle(socket);
	}

	/**
	 * The client over the socket that `dial` opens, once its session is
	 * ready. A dial that throws as it starts rejects the promise.
	 */
	static async #dial(parts: EngineParts, dial: () => Promise<MuxWsClient>): Promise<TightbeamWsClient> {
		const socket = await dial();
		const client = new TightbeamWsClient(parts, socket);
		return client;
	}

	/**
	 * Open a server-authenticated multiplexed session to `url` through the
	 * engine `parts`, as `Engine.connect` states.
	 *
	 * @internal
	 */
	static connect(
		parts: EngineParts,
		url: string,
		serverCertDer: Uint8Array,
		options?: ConnectOptions,
	): Promise<TightbeamWsClient> {
		const connector = parts.glue.MuxWsClient;
		const dialing = TightbeamWsClient.#dial(parts, () => connector.connect(url, serverCertDer, options));
		return dialing;
	}

	/**
	 * Open a mutually authenticated session to `url` through the engine
	 * `parts`, as `Engine.connectMutual` states.
	 *
	 * @internal
	 */
	static connectMutual(
		parts: EngineParts,
		url: string,
		identity: MutualIdentity,
		options?: MutualConnectOptions,
	): Promise<TightbeamWsClient> {
		const connector = parts.glue.MuxWsClient;
		const dialing = TightbeamWsClient.#dial(parts, () => connector.connectMutual(url, identity, options));
		return dialing;
	}

	/**
	 * Open a cleartext session to `url` through the engine `parts`, as
	 * `Engine.connectCleartext` states.
	 *
	 * @internal
	 */
	static connectCleartext(
		parts: EngineParts,
		url: string,
		options?: CleartextConnectOptions,
	): Promise<TightbeamWsClient> {
		const connector = parts.glue.MuxWsClient;
		const dialing = TightbeamWsClient.#dial(parts, () => connector.connectCleartext(url, options));
		return dialing;
	}

	/**
	 * The engine that dialed this client, which builds the frames it emits.
	 */
	get engine(): Engine {
		return this.#parts.engine;
	}

	/**
	 * A promise resolving when the socket closes, however that happens.
	 */
	get closed(): Promise<SocketCloseInfo> {
		return this.lifecycle.closed;
	}

	/**
	 * The socket's readyState (0 CONNECTING, 1 OPEN, 2 CLOSING, 3 CLOSED).
	 * A released client reports CLOSED.
	 */
	get readyState(): number {
		const readyState = this.lifecycle.view().readyState;
		return readyState;
	}

	/**
	 * Close the underlying socket and release its wasm resources, and resolve
	 * once the socket has closed, as {@link closed} does. A later close
	 * resolves as this one does, and emits in flight and every later call
	 * settle with `ConnectionClosed`.
	 */
	async close(): Promise<void> {
		this.lifecycle.release();
		await this.lifecycle.closed;
	}

	/**
	 * Close the client as an `await using` declaration leaves its scope, as
	 * {@link close} does.
	 */
	async [Symbol.asyncDispose](): Promise<void> {
		await this.close();
	}

	/**
	 * Send a built {@link Frame} on a fresh stream, and resolve with the
	 * decoded response frame, or `undefined` when the peer returns none. The
	 * stream takes its slot of the cap before the call returns. An abort of
	 * {@link EmitOptions.signal} cancels the stream with its abort reason.
	 */
	async emit(frame: Frame, options?: EmitOptions): Promise<Frame | undefined> {
		const socket = this.lifecycle.socket("emit");
		const response = await socket.request(frame.toDer(), options?.signal);

		const result = Frame.response(this.#parts, response);
		return result;
	}

	/**
	 * Submit a signed work frame through a cluster gateway to the servlet
	 * type that the URN `target` names, and resolve with the complete response
	 * frame of the servlet. Verify that frame before its body is trusted, as
	 * the cluster work submission section of `docs/ws-client.md` describes.
	 */
	async submitWork(target: string, work: Frame, options?: EmitOptions): Promise<Frame> {
		const socket = this.lifecycle.socket("submitWork");
		const der = work.toDer();
		const responseDer = await socket.submitWork(target, der, options?.signal);

		const response = Frame.decode(this.#parts, responseDer);
		return response;
	}

	/**
	 * Serve server-initiated streams with `handler`. The latest handler serves
	 * every stream that dispatches after the call.
	 *
	 * @throws TightbeamTransportError for a claim or a mode that the serve rules of the streams section of
	 * `docs/ws-client.md` refuse, such as `ServeModeConflict` once another mode started.
	 */
	serve(handler: MuxStreamHandler, options?: ServeOptions): void {
		const socket = this.lifecycle.socket("serve");
		const parts = this.#parts;

		const answer: UnaryServeHandler = (requestDer) => ServedStream.answerUnary(parts, handler, requestDer);
		socket.serve(answer, options?.claim);
	}

	/**
	 * Progressive client request: push body chunks, then close for a
	 * Frame response (or `undefined`). A disposal before
	 * {@link RequestStream.close} cancels the stream.
	 */
	openStream(): RequestStream {
		const socket = this.lifecycle.socket("openStream");

		const stream = socket.openStream();
		const request = new WasmRequest(this.#parts, stream);
		return request;
	}

	/**
	 * Progressive client request routed to a servlet URN. The Open carries the
	 * origin hop-budget sentinel, so the first gateway applies its clamp.
	 *
	 * @throws TightbeamTransportError `InvalidStreamRoute` for a `target` that
	 * is no URN of the form `urn:<nid>:<nss>`.
	 */
	openStreamTo(target: string): RequestStream {
		const socket = this.lifecycle.socket("openStreamTo");

		const stream = socket.openStreamTo(target);
		const request = new WasmRequest(this.#parts, stream);
		return request;
	}

	/**
	 * Full-duplex body streaming on one stream id. Pushes reach the socket
	 * eagerly, so a conversation that awaits the next chunk of
	 * {@link DuplexStream.body} between pushes is sound.
	 */
	openDuplex(): DuplexStream {
		const socket = this.lifecycle.socket("openDuplex");

		const stream = socket.openDuplex();
		const duplex = new WasmDuplex(stream);
		return duplex;
	}

	/**
	 * Duplex stream routed to a servlet URN. The Open carries the origin
	 * hop-budget sentinel, as {@link openStreamTo} states.
	 *
	 * @throws TightbeamTransportError `InvalidStreamRoute` for a `target` that
	 * is no URN of the form `urn:<nid>:<nss>`.
	 */
	openDuplexTo(target: string): DuplexStream {
		const socket = this.lifecycle.socket("openDuplexTo");

		const stream = socket.openDuplexTo(target);
		const duplex = new WasmDuplex(stream);
		return duplex;
	}

	/**
	 * Serve peer streams as progressive bodies. The handler receives the
	 * body chunks and the Open's {@link StreamRoute}. Mutually exclusive
	 * with {@link serve} / {@link serveDuplex}.
	 *
	 * @throws TightbeamTransportError as {@link serve} does.
	 */
	serveStreaming(handler: StreamingBodyHandler, options?: ServeOptions): void {
		const socket = this.lifecycle.socket("serveStreaming");

		const answer: StreamingServeHandler = (body, route) => ServedStream.answerStreaming(handler, body, route);
		socket.serveStreaming(answer, options?.claim);
	}

	/**
	 * Serve peer streams as duplex bodies. Mutually exclusive with
	 * {@link serve} / {@link serveStreaming}.
	 *
	 * @throws TightbeamTransportError as {@link serve} does.
	 */
	serveDuplex(handler: DuplexBodyHandler, options?: ServeOptions): void {
		const socket = this.lifecycle.socket("serveDuplex");

		const answer: DuplexServeHandler = (body, reply, route) =>
			ServedStream.answerDuplex(handler, body, reply, route);
		socket.serveDuplex(answer, options?.claim);
	}

	/**
	 * The negotiated cap on concurrent locally-initiated streams.
	 */
	get maxConcurrentStreams(): number {
		const maxConcurrentStreams = this.lifecycle.view().maxConcurrentStreams;
		return maxConcurrentStreams;
	}

	/**
	 * Whether a new stream would be admitted now: cap headroom, live ID
	 * space, and no GoAway either way.
	 *
	 * Advisory: a concurrent emit can take the last slot after this
	 * returns, so callers still handle the `StreamsExhausted` rejection.
	 */
	get hasStreamHeadroom(): boolean {
		const hasStreamHeadroom = this.lifecycle.view().hasStreamHeadroom;
		return hasStreamHeadroom;
	}

	/**
	 * Whether any emit still awaits its response, a pre-close check:
	 * {@link shutdown} drains these, and {@link close} settles them with
	 * `ConnectionClosed`. A concurrent emit or response can flip it after the
	 * read, as it can flip {@link hasStreamHeadroom}.
	 */
	get hasPendingStreams(): boolean {
		const hasPendingStreams = this.lifecycle.view().hasPendingStreams;
		return hasPendingStreams;
	}

	/**
	 * Resolves once a new stream would be admitted, in place of a poll of
	 * {@link hasStreamHeadroom}, and is advisory as that getter is. Rejects
	 * with `Draining` or `ConnectionClosed` once no stream will ever be
	 * admitted again, or with the abort reason of {@link WaitOptions.signal}.
	 */
	async waitForStreamSlot(options?: WaitOptions): Promise<void> {
		const socket = this.lifecycle.socket("waitForStreamSlot");

		await socket.waitForStreamSlot(options?.signal);
	}

	/**
	 * Reason carried by the peer's GoAway, or `undefined` while the connection
	 * is live or was shut down locally. A reconnect policy branches on it, as
	 * the reconnection section of `docs/ws-client.md` shows.
	 */
	get goawayReason(): GoAwayReason | undefined {
		const goawayReason = this.lifecycle.view().goawayReason;
		return goawayReason;
	}

	/**
	 * Numeric code behind {@link goawayReason}, or `undefined` while that
	 * getter is. Distinguishes application-defined codes that all label
	 * as `"application"`.
	 */
	get goawayCode(): number | undefined {
		const goawayCode = this.lifecycle.view().goawayCode;
		return goawayCode;
	}

	/**
	 * Usable outbound session-budget credits for this epoch, or
	 * `undefined` when unmetered. Invoice sizing uses this figure, which holds
	 * for every epoch of the session.
	 */
	get usableSendBudget(): number | undefined {
		const usableSendBudget = this.lifecycle.view().usableSendBudget;
		return usableSendBudget;
	}

	/**
	 * DER of the current epoch's dual-signed session receipt, or
	 * `undefined` on unmetered sessions. Rotates after each successful
	 * in-band renewal. Snapshotted by {@link close} like GoAway.
	 */
	get sessionReceiptDer(): Uint8Array | undefined {
		const sessionReceiptDer = this.lifecycle.view().sessionReceiptDer;
		return sessionReceiptDer;
	}

	/**
	 * Connection-level liveness probe, which resolves when the peer's ack
	 * arrives, as the keepalive section of `docs/ws-client.md` describes. It
	 * rejects with `Draining` while the connection winds down, with
	 * `ConnectionClosed` once it is gone, or with the abort reason of `signal`.
	 */
	async ping(options?: WaitOptions): Promise<void> {
		const socket = this.lifecycle.socket("ping");
		await socket.ping(options?.signal);
	}

	/**
	 * Gracefully shut the session down: sends GoAway, drains in-flight
	 * streams, then stops the writer. Follow with {@link close} to close
	 * the socket itself.
	 */
	async shutdown(): Promise<void> {
		const socket = this.lifecycle.socket("shutdown");
		await socket.shutdown();
	}

	/**
	 * As {@link shutdown}, advertising `reason` in the GoAway so the
	 * peer's reconnect policy can branch on it: a label or a numeric code.
	 * Codes outside the reserved range are application-defined, and the
	 * `"application"` label names no single code, so pass the number.
	 */
	async shutdownWith(reason: Exclude<GoAwayReason, "application"> | number): Promise<void> {
		const socket = this.lifecycle.socket("shutdownWith");
		await socket.shutdownWith(reason);
	}
}
