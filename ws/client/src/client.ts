/**
 * The WebSocket client: dial a tightbeam server, emit frames on multiplexed
 * streams, and serve the streams the server opens.
 */

import type {
	GoAwayReason,
	MuxDuplexStream,
	MuxReplySink,
	MuxRequestStream,
	MuxStreamBody,
	MuxWsClient,
	ServeClaim,
	SocketCloseInfo,
} from "#wasm";
import type { EngineInput } from "./engine.js";
import type { RefusalStatus } from "./errors.js";
import { ChunkSource } from "./chunks.js";
import { Engine } from "./engine.js";
import { ClientTransportError } from "./errors.js";
import { Frame } from "./frame.js";
import { Owned } from "./owned.js";
import { ServedStream } from "./served.js";

export type {
	CleartextConnectOptions,
	ConnectOptions,
	MutualConnectOptions,
} from "#wasm";

/**
 * The WebSocket CLOSED readyState, reported once the client has released
 * its socket.
 */
const WEBSOCKET_CLOSED = 3;

/**
 * The key of the package-internal constructor of a client over a socket
 * that the engine dialed. Only {@link Engine} imports it, so no caller hands
 * the client a raw wasm handle.
 */
export const OVER: unique symbol = Symbol("over");

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
 *
 * {@link release} hands the wasm object to its consuming close, so every
 * later wasm call would dereference a null pointer. A released state holds no
 * socket, only the snapshot taken at release, so no member can reach the
 * consumed object.
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
export type MuxStreamHandler = (
	frame: Frame,
) => Promise<Frame | undefined | null> | Frame | undefined | null;

/**
 * A progressive body. Each yield is one wire chunk, and the iteration ends
 * after the peer's `last` chunk.
 *
 * The body owns its wasm handle and frees it on every exit: the peer's
 * `last`, a failed read, a `break` or a `return` in a `for await` loop, and
 * the end of an `await using` scope. The body is single-use, and every
 * iteration shares it, so a `break` in one loop ends it for every loop.
 */
export interface StreamBody extends AsyncIterable<Uint8Array> {
	/**
	 * End the body and free its handle, which discards the chunks still to
	 * come. A later iteration yields nothing.
	 */
	[Symbol.asyncDispose](): Promise<void>;
}

/**
 * Open route stamped on a progressive or duplex stream: optional
 * servlet URN and remaining hop budget.
 */
export interface StreamRoute {
	/**
	 * Servlet target as `urn:<nid>:<nss>`, when the Open named one.
	 */
	target?: string;
	/**
	 * Remaining hop budget on this Open.
	 */
	hopsRemaining: number;
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
 * Reply half for {@link TightbeamWsClient.serveDuplex}.
 */
export interface ReplySink {
	/**
	 * Push one reply chunk toward the peer. Empty chunks are no-ops.
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
) => Promise<RefusalStatus | void> | RefusalStatus | void;

/**
 * Client-initiated progressive request: push chunks, then close for the
 * Frame response. `closeWith` flags the final chunk itself, spending
 * one record fewer than push-then-close.
 *
 * The calls on the stream run in the order they were made, so a close waits
 * for the pushes before it. The stream releases its wasm handle on every
 * exit. A close consumes the handle, and a disposal of an open stream cancels
 * it and frees the handle. Bind the stream with `await using`, so a throw or
 * a `break` cancels it.
 */
export interface RequestStream {
	/**
	 * Push one request chunk. Empty chunks are no-ops on the wire.
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
 * Client-initiated duplex stream. Pushes reach the wire eagerly, so a
 * chunk-for-chunk conversation is sound.
 *
 * - `closeWith` flags the final chunk itself.
 * - The calls on the request half run in the order they were made, so a close
 *   waits for the pushes before it.
 * - The request half and the reply {@link body} end apart. A close consumes
 *   the request half, and the body still reads until the peer's `last`.
 * - A disposal cancels the stream while either half is open, and frees both
 *   handles. Bind the stream with `await using`, so a throw cancels it.
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
	 * `exclusive` claim makes every later `serve*` call on this client throw
	 * a `TightbeamTransportError` whose `code` is `ServeDispatchClaimed`,
	 * instead of silently replacing the handler. It suits one dispatch owner
	 * (the `SubscriptionManager`) that composes application routes underneath
	 * itself.
	 */
	readonly claim?: ServeClaim;
}

/**
 * A wasm request half, which pushes one request chunk per call toward the
 * peer.
 */
type RequestHandle = Pick<MuxRequestStream, "push" | "free">;

/**
 * The request half of a client-initiated stream: its wasm handle, and the one
 * tail that every call on the half waits behind.
 *
 * - A call starts once the call before it settled, so a close waits for the
 *   pushes before it and never meets a push in flight.
 * - A call that starts at once reads its chunk before it returns. A call that
 *   waits reads a copy, so a later write to the chunk leaves the call as made.
 * - A close takes the handle for its consuming wasm close, a disposal frees an
 *   open handle at once, and a call after either one refuses with
 *   `StreamClosed`.
 */
class RequestHalf<T extends RequestHandle> implements Disposable {
	readonly #hold: Owned<T>;

	/**
	 * The last call on the half, settled either way.
	 */
	#tail: Promise<void> = Promise.resolve();

	/**
	 * The calls that have not settled yet.
	 */
	#queued = 0;

	constructor(stream: T) {
		this.#hold = new Owned(stream, ClientTransportError.streamClosed);
	}

	/**
	 * Push `chunk` at its turn.
	 */
	push(chunk: Uint8Array): Promise<void> {
		const octets = this.#readable(chunk);
		const pushing = async (): Promise<void> => {
			const stream = this.#hold.use("push");
			await stream.push(octets);
		};

		const pushed = this.#after(pushing);
		return pushed;
	}

	/**
	 * Run `closing`, the close `operation`, at its turn over the handle that
	 * it consumes.
	 */
	close<R>(
		operation: string,
		closing: (stream: T) => Promise<R>,
	): Promise<R> {
		const turn = async (): Promise<R> => {
			const stream = this.#hold.take(operation);
			const closed = await closing(stream);
			return closed;
		};

		const closed = this.#after(turn);
		return closed;
	}

	/**
	 * Run `closing`, which pushes `chunk` as the final chunk, at its turn over
	 * the handle that it consumes.
	 */
	closeWith<R>(
		chunk: Uint8Array,
		closing: (stream: T, last: Uint8Array) => Promise<R>,
	): Promise<R> {
		const octets = this.#readable(chunk);
		const finishing = (stream: T): Promise<R> => closing(stream, octets);

		const closed = this.close("closeWith", finishing);
		return closed;
	}

	/**
	 * Free an open handle at once. A push in flight holds its own share of the
	 * stream in wasm, so the stream cancels once that push settles.
	 */
	[Symbol.dispose](): void {
		this.#hold[Symbol.dispose]();
	}

	/**
	 * `chunk` as a call reads it: the chunk itself when the call starts at
	 * once, and a copy when the call waits behind another.
	 */
	#readable(chunk: Uint8Array): Uint8Array {
		if (this.#queued === 0) {
			return chunk;
		}

		const copy = chunk.slice();
		return copy;
	}

	/**
	 * Run `turn` once the call before it settles, or at once when no call is
	 * pending.
	 */
	#after<R>(turn: () => Promise<R>): Promise<R> {
		const previous = this.#tail;
		const waits = this.#queued > 0;
		const run = async (): Promise<R> => {
			if (waits) {
				await previous;
			}

			try {
				const ran = await turn();
				return ran;
			} finally {
				this.#queued -= 1;
			}
		};

		this.#queued += 1;
		const running = run();
		this.#tail = RequestHalf.#settled(running);
		return running;
	}

	/**
	 * Settle once `pending` settles, whether it resolves or rejects.
	 */
	static async #settled(pending: Promise<unknown>): Promise<void> {
		try {
			await pending;
		} catch {
			// The caller of the call receives its failure.
		}
	}
}

/**
 * The DER of a response frame, or `undefined` for a bodiless answer.
 */
type ResponseDer = Uint8Array | undefined;

/**
 * A client-initiated progressive request over its wasm stream, which decodes
 * the response frame. Its {@link RequestHalf} orders its calls and releases
 * the stream.
 */
class WasmRequest implements RequestStream {
	readonly #half: RequestHalf<MuxRequestStream>;

	readonly #engine: Engine;

	constructor(engine: Engine, stream: MuxRequestStream) {
		this.#engine = engine;
		this.#half = new RequestHalf(stream);
	}

	push(chunk: Uint8Array): Promise<void> {
		const pushed = this.#half.push(chunk);
		return pushed;
	}

	async close(): Promise<Frame | undefined> {
		const closing = (stream: MuxRequestStream): Promise<ResponseDer> =>
			stream.close();
		const der = await this.#half.close("close", closing);

		const response = Frame.response(this.#engine, der);
		return response;
	}

	async closeWith(chunk: Uint8Array): Promise<Frame | undefined> {
		const closing = (
			stream: MuxRequestStream,
			last: Uint8Array,
		): Promise<ResponseDer> => stream.closeWith(last);
		const der = await this.#half.closeWith(chunk, closing);

		const response = Frame.response(this.#engine, der);
		return response;
	}

	async [Symbol.asyncDispose](): Promise<void> {
		this.#half[Symbol.dispose]();
	}
}

/**
 * A client-initiated duplex stream over its wasm stream, whose reply body
 * reads through a handle of its own. Its {@link RequestHalf} orders the calls
 * on the request half and releases it.
 */
class WasmDuplex implements DuplexStream {
	readonly body: StreamBody;

	readonly #half: RequestHalf<MuxDuplexStream>;

	constructor(stream: MuxDuplexStream) {
		const body = stream.takeBody();
		this.body = new ChunkSource(body);
		this.#half = new RequestHalf(stream);
	}

	push(chunk: Uint8Array): Promise<void> {
		const pushed = this.#half.push(chunk);
		return pushed;
	}

	async close(): Promise<void> {
		const closing = (stream: MuxDuplexStream): Promise<void> =>
			stream.close();
		await this.#half.close("close", closing);
	}

	async closeWith(chunk: Uint8Array): Promise<void> {
		const closing = (
			stream: MuxDuplexStream,
			last: Uint8Array,
		): Promise<void> => stream.closeWith(last);
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
 * (`Engine.connectCleartext`).
 *
 * # Lifetime
 *
 * A client lives until {@link close}, the peer's close, or a GoAway. Garbage
 * collection is a backstop for a client the application leaked.
 *
 * - `await using` closes the client as its scope ends.
 * - Each stream the client opens releases its wasm handle on every exit:
 *   `close`, `closeWith`, and the end of an `await using` scope.
 * - The body and the reply half that a `serve*` handler receives free once the
 *   handler settles.
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
	readonly engine: Engine;

	private constructor(engine: Engine, socket: MuxWsClient) {
		this.engine = engine;
		this.lifecycle = new SocketLifecycle(socket);
	}

	/**
	 * Load the WebAssembly engine, and resolve with the {@link Engine} that
	 * proves it loaded. Every synchronous wasm-backed parse and constructor
	 * is an `Engine` method, so a call before this resolves does not
	 * type-check.
	 *
	 * The loader of the build condition imports its own glue here, so an
	 * import of the package never loads the binary. The web build starts the
	 * binary from `input`: a URL, a `Response`, the bytes, or a compiled
	 * `WebAssembly.Module`, for a custom host, a CSP-restricted page, or a
	 * worker. The Node build reads the binary beside its glue and ignores
	 * `input`.
	 *
	 * A realm loads one engine, so every call after the first resolves the
	 * same `Engine`, and a later `input` goes unread, as the glue leaves it
	 * once it started. {@link Engine.load} owns the load.
	 *
	 * @throws TightbeamTransportError `EngineUnavailable` when the binary is
	 * missing or does not start, with the platform failure as its `cause`.
	 */
	static init(input?: EngineInput): Promise<Engine> {
		const loading = Engine.load(input);
		return loading;
	}

	/**
	 * The client over `socket`, a session that `engine` dialed.
	 */
	static [OVER](engine: Engine, socket: MuxWsClient): TightbeamWsClient {
		const client = new TightbeamWsClient(engine, socket);
		return client;
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
	 * Close the underlying socket and release its wasm resources, and
	 * resolve once the socket has closed, as {@link closed} does.
	 * Idempotent, and safe with emits in flight: they settle with
	 * `ConnectionClosed`. Operations invoked afterwards reject with the
	 * same code.
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
	 * Send a built {@link Frame} on a fresh stream and resolve with the
	 * decoded response frame. Concurrent emits interleave on the
	 * connection. Responses correlate by stream.
	 *
	 * Resolves with `undefined` when the peer returns no response frame.
	 * An {@link EmitOptions.signal} abort cancels the stream and rejects
	 * with the signal's abort reason.
	 */
	async emit(
		frame: Frame,
		options?: EmitOptions,
	): Promise<Frame | undefined> {
		const socket = this.lifecycle.socket("emit");
		const der = frame.toDer();

		let response: Uint8Array | undefined;
		if (options?.signal === undefined) {
			response = await socket.request(der);
		} else {
			response = await socket.requestWithSignal(der, options.signal);
		}

		const result = Frame.response(this.engine, response);
		return result;
	}

	/**
	 * Submit a signed end-to-end work frame to the servlet type addressed
	 * by `target` (`urn:<nid>:<nss>`) through a cluster gateway, and
	 * resolve with the servlet's complete response frame.
	 *
	 * - The work frame's DER passes through byte-for-byte in both
	 *   directions, so its signature stays verifiable at the servlet.
	 * - The returned frame is the servlet's envelope with the same fidelity,
	 *   so verify it before trusting the message body. A served work always
	 *   carries a frame.
	 * - A gateway refusal rejects with a `TightbeamTransportError` whose
	 *   `code` is `WorkRefused` and whose `status` property names the gRPC
	 *   canonical status of the refusal.
	 * - An {@link EmitOptions.signal} abort cancels the stream and rejects
	 *   with the abort reason of the signal.
	 */
	async submitWork(
		target: string,
		work: Frame,
		options?: EmitOptions,
	): Promise<Frame> {
		const socket = this.lifecycle.socket("submitWork");

		let responseDer: Uint8Array;
		if (options?.signal === undefined) {
			responseDer = await socket.submitWork(target, work.toDer());
		} else {
			responseDer = await socket.submitWorkWithSignal(
				target,
				work.toDer(),
				options.signal,
			);
		}

		const response = this.engine.frame(responseDer);
		return response;
	}

	/**
	 * Serve server-initiated streams with `handler`.
	 *
	 * - The call is repeatable. The latest handler serves every stream that
	 *   dispatches after the call, and a stream in flight finishes on its own
	 *   handler. Handlers for distinct streams run concurrently.
	 * - The first `serve*` call picks the mode, so this call excludes
	 *   {@link serveStreaming} and {@link serveDuplex}.
	 * - The client stays open while it serves, as its class doc states.
	 *
	 * @throws TightbeamTransportError with code `ServeModeConflict` when a
	 * call in another mode already started, and `ServeDispatchClaimed` after
	 * an exclusive {@link ServeOptions.claim}.
	 */
	serve(handler: MuxStreamHandler, options?: ServeOptions): void {
		const socket = this.lifecycle.socket("serve");

		const answer = (
			requestDer: Uint8Array,
		): Promise<Uint8Array | undefined> =>
			this.answerUnary(handler, requestDer);
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
		const request = new WasmRequest(this.engine, stream);
		return request;
	}

	/**
	 * Progressive client request routed to a servlet URN
	 * (`urn:<nid>:<nss>`). The Open carries the origin hop-budget
	 * sentinel so the first gateway applies its `max_hops` clamp.
	 *
	 * @throws TightbeamTransportError with code `InvalidStreamRoute`
	 * when `target` is not a URN.
	 */
	openStreamTo(target: string): RequestStream {
		const socket = this.lifecycle.socket("openStreamTo");

		const stream = socket.openStreamTo(target);
		const request = new WasmRequest(this.engine, stream);
		return request;
	}

	/**
	 * Full-duplex body streaming on one stream id.
	 *
	 * Pushes reach the wire eagerly: awaiting the next chunk of
	 * {@link DuplexStream.body} between pushes (a chunk-for-chunk
	 * conversation) is sound. {@link DuplexStream.closeWith} flags
	 * the final chunk itself.
	 */
	openDuplex(): DuplexStream {
		const socket = this.lifecycle.socket("openDuplex");

		const stream = socket.openDuplex();
		const duplex = new WasmDuplex(stream);
		return duplex;
	}

	/**
	 * Duplex stream routed to a servlet URN (`urn:<nid>:<nss>`).
	 *
	 * As {@link openStreamTo}: the Open carries the origin hop-budget
	 * sentinel so the first gateway applies its `max_hops` clamp.
	 *
	 * @throws TightbeamTransportError with code `InvalidStreamRoute`
	 * when `target` is not a URN.
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
	serveStreaming(
		handler: StreamingBodyHandler,
		options?: ServeOptions,
	): void {
		const socket = this.lifecycle.socket("serveStreaming");

		const answer = (
			body: MuxStreamBody,
			route: StreamRoute,
		): Promise<Uint8Array | undefined> =>
			ServedStream.answerStreaming(handler, body, route);
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

		const answer = (
			body: MuxStreamBody,
			reply: MuxReplySink,
			route: StreamRoute,
		): Promise<string | undefined> =>
			ServedStream.answerDuplex(handler, body, reply, route);
		socket.serveDuplex(answer, options?.claim);
	}

	/**
	 * Answer one server-initiated unary stream with `handler`.
	 */
	private async answerUnary(
		handler: MuxStreamHandler,
		requestDer: Uint8Array,
	): Promise<Uint8Array | undefined> {
		const request = this.engine.frame(requestDer);
		const response = await handler(request);
		if (response === undefined || response === null) {
			return undefined;
		}

		const responseDer = response.toDer();
		return responseDer;
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
	 * Whether any emit still awaits its response. A pre-close check:
	 * {@link shutdown} drains these, {@link close} settles them with
	 * `ConnectionClosed`.
	 *
	 * Advisory: like {@link hasStreamHeadroom}: a concurrent emit or
	 * response can flip it after the read.
	 */
	get hasPendingStreams(): boolean {
		const hasPendingStreams = this.lifecycle.view().hasPendingStreams;
		return hasPendingStreams;
	}

	/**
	 * Resolves once a new stream would be admitted. Replaces polling
	 * {@link hasStreamHeadroom} in a loop, with the same advisory caveat.
	 *
	 * Rejects with `Draining` or `ConnectionClosed` once no stream will ever
	 * be admitted again, or with the abort reason of
	 * {@link WaitOptions.signal} when the caller gives up first.
	 */
	async waitForStreamSlot(options?: WaitOptions): Promise<void> {
		const socket = this.lifecycle.socket("waitForStreamSlot");

		await socket.waitForStreamSlot(options?.signal);
	}

	/**
	 * Reason carried by the peer's GoAway, or `undefined` while the
	 * connection is live or was shut down locally.
	 *
	 * Reconnect policies branch on this: `shutdown` invites an immediate
	 * reconnect, `enhance-your-calm` calls for backoff, and `protocol-error`
	 * points at a bug rather than a transient fault.
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
	 * `undefined` when unmetered. Invoice sizing uses this figure.
	 * There is no live remaining-balance getter.
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
	 * Connection-level liveness probe: resolves when the peer's ack
	 * arrives. No stream is allocated and the peer's application handler
	 * never runs. A client already pings on its own to hold an idle session
	 * open, so call this to measure the link.
	 *
	 * The promise rejects with one of these:
	 *
	 * - `Draining` while the connection winds down.
	 * - `ConnectionClosed` once it is gone.
	 * - The abort reason of {@link WaitOptions.signal} when a deadline fires
	 *   first (`AbortSignal.timeout(ms)`).
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
	async shutdownWith(
		reason: Exclude<GoAwayReason, "application"> | number,
	): Promise<void> {
		const socket = this.lifecycle.socket("shutdownWith");
		await socket.shutdownWith(reason);
	}
}
