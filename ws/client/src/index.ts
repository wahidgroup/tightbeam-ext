/**
 * Client for the tightbeam WebSocket transport (browser and Node).
 */

import init, { MuxWsClient } from "#wasm";
import type { GoAwayReason, SocketCloseInfo, TransportSigner } from "#wasm";

import type { MessageCodec } from "./message.js";
import { FrameBuilder } from "./builder/index.js";
import { WasmFrameCodec } from "./codec.js";
import { Envelope } from "./envelope.js";
import { connectionClosed } from "./errors.js";
import { Frame } from "./frame.js";

export type { MuxWsClient };
export type { GoAwayReason, SocketCloseInfo, TransportSigner } from "#wasm";
export {
	InternalError,
	StreamRefusal,
	TRANSPORT_ERROR_NAME,
	isTransportError,
} from "./errors.js";
export type { TransitCode, TransportError } from "./errors.js";
export { WasmFrameCodec } from "./codec.js";
export { Frame, Framed, INTEGRITY_VERDICTS } from "./frame.js";
export type {
	CompactnessInfo,
	ConfidentialityInfo,
	DigestInfo,
	FrameMatrix,
	IntegrityVerdict,
	PreviousFrame,
	SignatureInfo,
} from "./frame.js";
export { Opening } from "./commitment.js";
export type { ProvenCommitment } from "./commitment.js";
export { ZstdCompression } from "./compress.js";
export type {
	BodyCompressor,
	BodyInflator,
	CompressedBody,
} from "./compress.js";
export {
	Aes256Gcm,
	EciesDecryptor,
	EciesEncryptor,
	PROFILE_OIDS,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	Sha3_256,
} from "./crypto.js";
export type {
	BodyDecryptor,
	BodyEncryptor,
	EncryptedBody,
	Hasher,
	Signatory,
} from "./crypto.js";
export { Envelope } from "./envelope.js";
export { Opaque, wrapped } from "./message.js";
export type { MessageCodec, PayloadCodec } from "./message.js";
export { UnroutedTopicError, route, router } from "./router.js";
export type { Route, RouteHandler } from "./router.js";
export {
	FrameBuilder,
	MessagePriority,
	ValidationError,
	Version,
	priorityFromOrdinal,
	versionFromOrdinal,
} from "./builder/index.js";
export type {
	FrameCodec,
	FrameSpec,
	MatrixSpec,
	MessageIntegritySpec,
	MessageSlot,
	PreviousHashSpec,
	ValidationIssue,
} from "./builder/index.js";

/**
 * The wasm-backed codec shared by {@link frame}.
 */
const sharedCodec = new WasmFrameCodec();

/**
 * Begin building a tightbeam frame with the fluent builder (same API as
 * the tightbeam-rs `compose!` surface), backed by the WebAssembly codec.
 *
 * The wasm module MUST be initialized via {@link initClient} before calling
 * {@link FrameBuilder.build}.
 */
export function frame(message?: Uint8Array): FrameBuilder {
	const builder = new FrameBuilder(sharedCodec);
	if (message === undefined) {
		return builder;
	}

	const builderWithMessage = builder.withMessage(message);
	return builderWithMessage;
}

/**
 * Begin a typed message {@link Envelope} over `codec`, backed by the
 * WebAssembly frame codec: declare the layers once (`signed`, `sealed`,
 * `compressed`), then build with `envelope.frame(message)` and receive
 * with `envelope.unwrap(frame)`. Declared layers are enforced on unwrap.
 */
export function envelope<T>(codec: MessageCodec<T>): Envelope<T> {
	const begun = Envelope.over(sharedCodec, codec);
	return begun;
}

/**
 * The lifecycle surface shared by every wasm socket.
 */
interface LifecycleSocket {
	readonly closed: Promise<SocketCloseInfo>;
	readonly readyState: number;
	close(): void;
	free(): void;
}

/**
 * The WebSocket CLOSED readyState, reported once the client has released
 * its socket.
 */
const WEBSOCKET_CLOSED = 3;

/**
 * Base for the wasm-socket clients: lifecycle observation and idempotent
 * release.
 *
 * {@link close} frees the wasm object, so every later wasm call would
 * dereference a null pointer. Members guard with {@link requireLive}
 * (defined `ConnectionClosed` rejection) or serve release-time snapshots
 * instead of touching the socket.
 */
abstract class SocketLifecycle<TSocket extends LifecycleSocket> {
	private released = false;

	/**
	 * Captured at construction so closure stays observable after
	 * {@link close} frees the wasm object.
	 */
	private readonly closedPromise: Promise<SocketCloseInfo>;

	protected constructor(protected readonly socket: TSocket) {
		this.closedPromise = socket.closed;
	}

	/**
	 * Whether {@link close} has released the wasm resources.
	 */
	protected get isReleased(): boolean {
		return this.released;
	}

	/**
	 * Guard for members that call into the wasm object.
	 *
	 * @throws A `ConnectionClosed` transport error after {@link close}.
	 */
	protected requireLive(operation: string): void {
		if (this.released) {
			throw connectionClosed(operation);
		}
	}

	/**
	 * Snapshot the state that stays readable after release. Runs once
	 * inside {@link close}, while the socket is still live.
	 */
	protected abstract snapshot(): void;

	/**
	 * A promise resolving when the socket closes, however that happens.
	 */
	get closed(): Promise<SocketCloseInfo> {
		return this.closedPromise;
	}

	/**
	 * The socket's readyState (0 CONNECTING, 1 OPEN, 2 CLOSING, 3 CLOSED).
	 * A released client reports CLOSED.
	 */
	get readyState(): number {
		if (this.released) {
			return WEBSOCKET_CLOSED;
		}

		return this.socket.readyState;
	}

	/**
	 * Close the underlying socket and release its wasm resources. The
	 * {@link closed} promise resolves once the close completes.
	 * Idempotent, and safe with emits in flight: they settle with
	 * `ConnectionClosed`. Operations invoked afterwards reject with the
	 * same code.
	 */
	close(): void {
		if (this.released) {
			return;
		}

		this.snapshot();
		this.released = true;
		this.socket.close();
		this.socket.free();
	}
}

/**
 * Decode a response frame's DER: `undefined` means the peer returned no
 * response frame.
 */
function decodeResponse(response: Uint8Array | undefined): Frame | undefined {
	if (response === undefined) {
		return undefined;
	}

	const result = Frame.fromDer(response);
	return result;
}

/**
 * Send a frame over `socket` and decode the response: resolves with
 * `undefined` when the peer returns no response frame.
 */
async function emitFrame(
	socket: MuxWsClient,
	frame: Frame,
	options?: EmitOptions,
): Promise<Frame | undefined> {
	let response: Uint8Array | undefined;
	if (options?.signal === undefined) {
		response = await socket.request(frame.toDer());
	} else {
		response = await socket.requestWithSignal(
			frame.toDer(),
			options.signal,
		);
	}

	const result = decodeResponse(response);
	return result;
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
 * Options accepted by the encrypted {@link TightbeamWsClient} connectors
 * ({@link TightbeamWsClient.connect}, {@link TightbeamWsClient.connectMutual}).
 */
export interface ConnectOptions {
	/**
	 * Abort the dial and handshake: the socket closes and the promise
	 * rejects with the signal's abort reason. Timeouts compose as
	 * `AbortSignal.timeout(ms)`.
	 */
	signal?: AbortSignal;
	/**
	 * Concurrency cap granted to server-initiated streams (default 8).
	 * The server's own advertisement caps this client's concurrent emits.
	 */
	maxPeerStreams?: number;
}

/**
 * Options accepted by {@link TightbeamWsClient.connectCleartext}.
 */
export interface CleartextConnectOptions {
	/**
	 * Abort the dial: the socket closes and the promise rejects with
	 * the signal's abort reason. Timeouts compose as `AbortSignal.timeout(ms)`.
	 */
	signal?: AbortSignal;
	/**
	 * Symmetric concurrency cap (default 8). Cleartext sessions have no
	 * negotiation, so both endpoints MUST configure the same value.
	 */
	streams?: number;
}

/**
 * The default stream cap shared by every connector.
 */
const DEFAULT_STREAM_CAP = 8;

/**
 * Reject a non-object options argument loudly: a number here would
 * otherwise cross into wasm as a bogus stream cap while the intended
 * options are silently dropped.
 */
function assertOptionsShape(options: unknown): void {
	if (options === undefined) {
		return;
	}
	if (typeof options === "object" && options !== null) {
		return;
	}

	throw new TypeError(
		"connect options must be an object: stream caps are options fields (maxPeerStreams / streams), not positional arguments",
	);
}

/**
 * The largest cap the wasm u32 boundary can carry.
 */
const MAX_STREAM_CAP = 0xff_ff_ff_ff;

/**
 * Reject a cap the wasm u32 boundary would silently coerce: negatives
 * wrap to huge values, fractions truncate, and zero deadlocks the
 * session before its first stream.
 */
function assertStreamCap(field: string, cap: number): void {
	const representable =
		Number.isSafeInteger(cap) && cap >= 1 && cap <= MAX_STREAM_CAP;
	if (representable) {
		return;
	}

	throw new TypeError(
		`${field} is not a usable stream cap: expected an integer between 1 and ${MAX_STREAM_CAP}, got ${cap}`,
	);
}

/**
 * Reject a client key that is neither a raw scalar nor signer-shaped
 * before it reaches wasm: an ArrayBuffer (the WebCrypto `exportKey`
 * shape) or any stray object would otherwise follow the signer path and
 * fail with a misleading signer error.
 */
function assertClientKeyShape(clientKey: Uint8Array | TransportSigner): void {
	if (clientKey instanceof Uint8Array) {
		return;
	}
	if (typeof clientKey === "object" && clientKey !== null) {
		const algorithmOid: unknown = Reflect.get(clientKey, "algorithmOid");
		const publicKeyDer: unknown = Reflect.get(clientKey, "publicKeyDer");
		const signPrehash: unknown = Reflect.get(clientKey, "signPrehash");
		const signerShaped =
			typeof algorithmOid === "string" &&
			publicKeyDer instanceof Uint8Array &&
			typeof signPrehash === "function";
		if (signerShaped) {
			return;
		}
	}

	throw new TypeError(
		"clientKey must be the raw signing scalar as a Uint8Array (wrap ArrayBuffers) or a TransportSigner exposing algorithmOid, publicKeyDer, and signPrehash",
	);
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

let initialization: Promise<void> | undefined;

/**
 * Load the WebAssembly module once. Subsequent calls await the same load.
 *
 * Under Node the module is compiled synchronously at import time (the
 * `nodejs` wasm-pack target), so this resolves immediately.
 */
export async function initClient(
	input?: Parameters<typeof init>[0],
): Promise<void> {
	if (initialization === undefined) {
		initialization = (async (): Promise<void> => {
			const load: unknown = init;
			if (typeof load === "function") {
				await init(input);
			}
		})();
	}

	await initialization;
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
 * Options accepted by {@link TightbeamWsClient.serve}.
 */
export interface ServeOptions {
	/**
	 * Claim stream dispatch exclusively: every later `serve` call on
	 * this client throws instead of silently replacing the handler.
	 * For one dispatch owner (the `SubscriptionManager`) composing
	 * application routes underneath itself.
	 */
	readonly exclusive?: boolean;
}

/**
 * A multiplexed tightbeam client over a single WebSocket session,
 * ECIES-encrypted ({@link connect}, {@link connectMutual}) or cleartext
 * ({@link connectCleartext}).
 */
export class TightbeamWsClient extends SocketLifecycle<MuxWsClient> {
	/**
	 * GoAway facts and the negotiated cap, snapshotted by {@link close}
	 * so reconnect policies can still read them from a released client.
	 */
	private finalGoawayReason: GoAwayReason | undefined;
	private finalGoawayCode: number | undefined;
	private finalMaxConcurrentStreams = 0;

	/**
	 * Set by an {@link ServeOptions.exclusive} claim: dispatch belongs
	 * to one owner and later {@link serve} calls throw.
	 */
	private serveClaimed = false;

	private constructor(socket: MuxWsClient) {
		super(socket);
	}

	protected snapshot(): void {
		this.finalGoawayReason = this.socket.goawayReason;
		this.finalGoawayCode = this.socket.goawayCode;
		this.finalMaxConcurrentStreams = this.socket.maxConcurrentStreams;
	}

	/**
	 * Initialize the module (if needed) and open a server-authenticated
	 * multiplexed session to `url`. Resolves once the handshake completes
	 * and multiplexing is negotiated.
	 *
	 * @param url - The WebSocket URL to connect to.
	 * @param serverCertDer - DER certificate pinned as the trusted server.
	 * @param options - {@link ConnectOptions.maxPeerStreams} caps
	 * server-initiated streams. {@link ConnectOptions.signal} aborts the
	 * dial and handshake.
	 */
	static async connect(
		url: string,
		serverCertDer: Uint8Array,
		options?: ConnectOptions,
	): Promise<TightbeamWsClient> {
		assertOptionsShape(options);

		const maxPeerStreams = options?.maxPeerStreams ?? DEFAULT_STREAM_CAP;
		assertStreamCap("maxPeerStreams", maxPeerStreams);

		await initClient();

		const socket = await MuxWsClient.connect(
			url,
			serverCertDer,
			maxPeerStreams,
			options?.signal,
		);

		const client = new TightbeamWsClient(socket);
		return client;
	}

	/**
	 * Initialize the module (if needed) and open a cleartext multiplexed
	 * session to `url`.
	 *
	 * Cleartext multiplexing has no handshake negotiation: the cap is
	 * symmetric and both endpoints MUST configure the same value. The
	 * connection carries NO confidentiality or integrity protection.
	 *
	 * Resolves once the socket is open, matching {@link connect}: a
	 * failed dial rejects here rather than on the first emit.
	 *
	 * @param url - The WebSocket URL to connect to.
	 * @param options - {@link CleartextConnectOptions.streams} sets the
	 * symmetric cap. {@link CleartextConnectOptions.signal} aborts the dial.
	 */
	static async connectCleartext(
		url: string,
		options?: CleartextConnectOptions,
	): Promise<TightbeamWsClient> {
		assertOptionsShape(options);

		const streams = options?.streams ?? DEFAULT_STREAM_CAP;
		assertStreamCap("streams", streams);

		await initClient();

		const socket = await MuxWsClient.connectCleartext(
			url,
			streams,
			options?.signal,
		);

		const client = new TightbeamWsClient(socket);
		return client;
	}

	/**
	 * As {@link connect}, additionally presenting a client identity for
	 * mutual authentication. Possession of the certificate key is proven
	 * either by the raw 32-byte secp256k1 signing scalar or by an external
	 * {@link TransportSigner} (WebAuthn, wallet, KMS bridge), in which case
	 * the private key never leaves its backend.
	 *
	 * @param url - The WebSocket URL to connect to.
	 * @param serverCertDer - DER certificate pinned as the trusted server.
	 * @param clientCertDer - DER certificate presented to the server.
	 * @param clientKey - secp256k1 signing scalar, or an external signer.
	 * @param options - {@link ConnectOptions.maxPeerStreams} caps
	 * server-initiated streams. {@link ConnectOptions.signal} aborts the
	 * dial and handshake.
	 */
	static async connectMutual(
		url: string,
		serverCertDer: Uint8Array,
		clientCertDer: Uint8Array,
		clientKey: Uint8Array | TransportSigner,
		options?: ConnectOptions,
	): Promise<TightbeamWsClient> {
		assertOptionsShape(options);
		assertClientKeyShape(clientKey);
		const maxPeerStreams = options?.maxPeerStreams ?? DEFAULT_STREAM_CAP;
		assertStreamCap("maxPeerStreams", maxPeerStreams);
		await initClient();

		let socket: MuxWsClient;
		if (clientKey instanceof Uint8Array) {
			socket = await MuxWsClient.connectMutual(
				url,
				serverCertDer,
				clientCertDer,
				clientKey,
				maxPeerStreams,
				options?.signal,
			);
		} else {
			socket = await MuxWsClient.connectMutualWithSigner(
				url,
				serverCertDer,
				clientCertDer,
				clientKey,
				maxPeerStreams,
				options?.signal,
			);
		}

		const client = new TightbeamWsClient(socket);
		return client;
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
		this.requireLive("emit");

		const result = await emitFrame(this.socket, frame, options);
		return result;
	}

	/**
	 * Serve server-initiated streams with `handler`. Callable repeatedly:
	 * the latest handler serves every stream dispatched after the call,
	 * and streams already in flight finish on the handler they started
	 * with. Handlers for distinct streams run concurrently.
	 */
	serve(handler: MuxStreamHandler, options?: ServeOptions): void {
		this.requireLive("serve");
		if (this.serveClaimed) {
			throw new Error(
				"stream dispatch is exclusively claimed on this client " +
					"(a SubscriptionManager?); route application streams " +
					"through the claimant instead of calling serve again",
			);
		}
		if (options?.exclusive === true) {
			this.serveClaimed = true;
		}

		this.socket.serve(
			(requestDer: Uint8Array): Promise<Uint8Array | undefined> => {
				const respond = async (): Promise<Uint8Array | undefined> => {
					const request = Frame.fromDer(requestDer);
					const response = await handler(request);
					if (response === undefined || response === null) {
						return undefined;
					}

					const responseDer = response.toDer();
					return responseDer;
				};

				const settled = respond();
				return settled;
			},
		);
	}

	/**
	 * The negotiated cap on concurrent locally-initiated streams.
	 */
	get maxConcurrentStreams(): number {
		if (this.isReleased) {
			return this.finalMaxConcurrentStreams;
		}

		return this.socket.maxConcurrentStreams;
	}

	/**
	 * Whether a new stream would be admitted now: cap headroom, live ID
	 * space, and no GoAway either way.
	 *
	 * Advisory: a concurrent emit can take the last slot after this
	 * returns, so callers still handle the `StreamsExhausted` rejection.
	 */
	get hasStreamHeadroom(): boolean {
		if (this.isReleased) {
			return false;
		}

		return this.socket.hasStreamHeadroom;
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
		if (this.isReleased) {
			return false;
		}

		return this.socket.hasPendingStreams;
	}

	/**
	 * Resolves once a new stream would be admitted. Replaces polling
	 * {@link hasStreamHeadroom} in a loop, with the same advisory caveat.
	 *
	 * Rejects with `Draining` once no stream will ever be admitted again,
	 * or with the abort reason of {@link WaitOptions.signal} when the
	 * caller gives up first.
	 */
	async waitForStreamSlot(options?: WaitOptions): Promise<void> {
		this.requireLive("waitForStreamSlot");

		await this.socket.waitForStreamSlot(options?.signal);
	}

	/**
	 * Reason carried by the peer's GoAway, or `undefined` while the
	 * connection is live or was shut down locally.
	 *
	 * Reconnect policies branch on this: `Shutdown` invites an immediate
	 * reconnect, `EnhanceYourCalm` calls for backoff, and `ProtocolError`
	 * points at a bug rather than a transient fault.
	 */
	get goawayReason(): GoAwayReason | undefined {
		if (this.isReleased) {
			return this.finalGoawayReason;
		}

		return this.socket.goawayReason;
	}

	/**
	 * Numeric code behind {@link goawayReason}, or `undefined` while that
	 * getter is. Distinguishes application-defined codes that all label
	 * as `"Application"`.
	 */
	get goawayCode(): number | undefined {
		if (this.isReleased) {
			return this.finalGoawayCode;
		}

		return this.socket.goawayCode;
	}

	/**
	 * Connection-level liveness probe: resolves when the peer's ack
	 * arrives. No stream is allocated and the peer's application handler
	 * never runs, so a periodic ping doubles as an idle keepalive.
	 *
	 * Rejects with `Draining` while the connection winds down,
	 * `ConnectionClosed` when it is gone, and the abort reason of
	 * {@link WaitOptions.signal} when a deadline fires first
	 * (`AbortSignal.timeout(ms)`).
	 */
	async ping(options?: WaitOptions): Promise<void> {
		this.requireLive("ping");

		await this.socket.ping(options?.signal);
	}

	/**
	 * Gracefully shut the session down: sends GoAway, drains in-flight
	 * streams, then stops the writer. Follow with {@link close} to close
	 * the socket itself.
	 */
	async shutdown(): Promise<void> {
		this.requireLive("shutdown");

		await this.socket.shutdown();
	}

	/**
	 * As {@link shutdown}, advertising `reason` in the GoAway so the
	 * peer's reconnect policy can branch on it: a label (`"Shutdown"`,
	 * `"ProtocolError"`, `"EnhanceYourCalm"`) or a numeric code.
	 * Codes outside the reserved range are application-defined.
	 */
	async shutdownWith(reason: GoAwayReason | number): Promise<void> {
		this.requireLive("shutdownWith");

		await this.socket.shutdownWith(reason);
	}
}
