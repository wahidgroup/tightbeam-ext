/**
 * Error surface for the browser client.
 *
 * Every code a caller branches on has one declaration. The engine declares
 * {@link RefusalCode}, {@link TransportCode}, and {@link TransitCode} in Rust,
 * and the declarations of the wasm build carry each one as a union. This
 * module declares {@link ClientCode}, the codes that the TypeScript client
 * decides itself.
 */

import type {
	RefusalCode,
	TransitCode,
	TransportCode,
	TransportErrorName,
} from "#wasm";

/**
 * The code of an {@link InternalError}: a step of the client that ran out of
 * the order its owner keeps.
 *
 * - `MESSAGE_ARITY`: `withMessage` received a codec without its message.
 * - `COMPOSER_SPENT`: a build step set the composer after it assembled the frame.
 * - `ASSEMBLY_SPENT`: a build step ran after an earlier step consumed the assembly.
 */
export type InternalCode =
	"MESSAGE_ARITY" | "COMPOSER_SPENT" | "ASSEMBLY_SPENT";

/**
 * Represents internal client errors, such as protocol violations by the
 * peer. Not safe to display to end users.
 */
export class InternalError extends Error {
	/**
	 * Discriminant for the internal error family.
	 */
	readonly kind = "E_INTERNAL";

	/**
	 * Stable programmatic code for branching on this failure.
	 */
	readonly code: InternalCode;

	constructor(code: InternalCode, message: string, cause?: unknown) {
		super(message, { cause });
		this.name = this.constructor.name;
		this.code = code;
	}
}

/**
 * The gRPC canonical status (`google.rpc.Code`) that a serve handler refuses
 * a stream with. `Ok` names no refusal: a returned frame or `undefined`
 * already accepts the stream.
 */
export type RefusalStatus = Exclude<TransitCode, "Ok">;

/**
 * Refuse a server-initiated stream with a chosen status.
 *
 * Thrown (or rejected with) from a `serve` handler, the wasm layer
 * answers the stream with `code` instead of the generic `Unknown`, so
 * the peer receives the application's own refusal semantics.
 */
export class StreamRefusal extends Error {
	override readonly name: string = "StreamRefusal";

	/**
	 * gRPC canonical status name answered to the peer for this refusal.
	 */
	readonly code: RefusalStatus;

	constructor(code: RefusalStatus, message: string) {
		super(message);
		this.code = code;
	}
}

/**
 * The key of the package-internal check whether a code is a code the client
 * decides itself. Only `Engine` imports it.
 */
export const DECIDES: unique symbol = Symbol("decides");

/**
 * The key of the package-internal read of the code of an error with the name
 * brand of a transport error. Only `Engine` imports it.
 */
export const BRANDED_CODE: unique symbol = Symbol("brandedCode");

/**
 * Every code of a failure that the TypeScript client decides itself, before
 * a call reaches the engine. {@link ClientCode} reads its members from this
 * one list.
 *
 * - `KeyReleased`: a profile key whose owner released its wasm handle.
 * - `OpeningReleased`: a commitment opening whose owner released its salt.
 * - `CodecReleased`: a held codec whose holder disposed it.
 * - `EngineUnavailable`: the WebAssembly engine did not load.
 */
const CLIENT_CODES = [
	"KeyReleased",
	"OpeningReleased",
	"CodecReleased",
	"EngineUnavailable",
] as const;

/**
 * The code of a failure that the TypeScript client decides itself.
 */
export type ClientCode = (typeof CLIENT_CODES)[number];

/**
 * Every code a {@link TransportError} carries: a refusal of the engine, an
 * engine or transport error, a peer refusal by its status, or a failure the
 * client decides itself.
 */
export type TransportErrorCode =
	RefusalCode | TransportCode | RefusalStatus | ClientCode;

/**
 * A transport failure thrown from the wasm layer, or decided by the client
 * before a call crosses the boundary.
 *
 * `code` is closed: every value is a member of {@link TransportErrorCode}.
 * The codes callers most often branch on:
 *
 * - `ConnectionClosed`: the connection ended. It outranks `Draining`, so a
 *   finished `shutdown()` reads as closed.
 * - `Draining`: GoAway sent or received on a live connection. No new streams.
 * - `StreamsExhausted`: the local stream cap is full. Retry after a
 *   response frees a slot.
 *
 * Peer refusals carry the gRPC canonical status registry
 * (`google.rpc.Code`) name for their code:
 *
 * - `ResourceExhausted`: the peer refused the stream at capacity. Retry with backoff.
 * - `Unavailable`: the peer is draining or shutting down. Retry with backoff.
 * - `Unimplemented`: nothing serves the requested topic. A retry cannot succeed.
 * - `Unknown`: the peer's handler failed without classification.
 * - `DeadlineExceeded`, `Unauthenticated`, `PermissionDenied`: gate policy rejections.
 */
export interface TransportError extends Error {
	readonly name: TransportErrorName;

	/**
	 * The code that names the failure.
	 */
	readonly code: TransportErrorCode;

	/**
	 * The field a refusal concerns, as a TypeScript access such as
	 * `matrix.n`, when the refusal concerns one.
	 */
	readonly path?: string;

	/**
	 * The transit status of a refused work submission, on `WorkRefused`.
	 */
	readonly status?: TransitCode;
}

/**
 * A {@link TransportError} that the client decides before a call crosses the
 * boundary. The class owns the decisions over the family: one named static
 * builds each code, and the constructor is private.
 */
export class ClientTransportError extends Error implements TransportError {
	/**
	 * The `name` of every structured transport error, which the engine sets on
	 * its own errors too.
	 */
	static readonly NAME: TransportErrorName = "TightbeamTransportError";

	override readonly name = ClientTransportError.NAME;

	readonly code: TransportErrorCode;

	private constructor(
		code: TransportErrorCode,
		message: string,
		options?: ErrorOptions,
	) {
		super(message, options);
		this.code = code;
	}

	/**
	 * The rejection for `operation` on a released client: the same
	 * `ConnectionClosed` code that in-flight emits settle with when the
	 * connection drops.
	 */
	static closed(operation: string): ClientTransportError {
		const message = `Cannot ${operation}: the client is closed and its wasm resources are released`;
		const closed = new ClientTransportError("ConnectionClosed", message);
		return closed;
	}

	/**
	 * The rejection for `operation` on a stream whose owner closed or
	 * released its wasm handle: the same `StreamClosed` code that the wasm
	 * layer gives a stream half that a close consumed.
	 */
	static streamClosed(operation: string): ClientTransportError {
		const message = `Cannot ${operation}: the stream is closed and its wasm handle is released`;
		const closed = new ClientTransportError("StreamClosed", message);
		return closed;
	}

	/**
	 * The rejection for `operation` on a profile key whose wasm handle its
	 * owner released.
	 */
	static keyReleased(operation: string): ClientTransportError {
		const message = `Cannot ${operation}: the key is released and its wasm handle is freed`;
		const released = new ClientTransportError("KeyReleased", message);
		return released;
	}

	/**
	 * The rejection for `operation` on a commitment opening whose owner
	 * released its salt.
	 */
	static openingReleased(operation: string): ClientTransportError {
		const message = `Cannot ${operation}: the opening is released and its salt is freed`;
		const released = new ClientTransportError("OpeningReleased", message);
		return released;
	}

	/**
	 * The rejection for `operation` on a held codec whose holder disposed it
	 * and freed its copy of the content type.
	 */
	static codecReleased(operation: string): ClientTransportError {
		const message = `Cannot ${operation}: the codec is released and its content type is freed`;
		const released = new ClientTransportError("CodecReleased", message);
		return released;
	}

	/**
	 * The rejection of an engine load that failed with `cause`: the binary is
	 * missing, the platform refused it, or its glue failed to start.
	 */
	static engineUnavailable(cause: unknown): ClientTransportError {
		const message = "The WebAssembly engine did not load";
		const options = { cause };

		const unavailable = new ClientTransportError(
			"EngineUnavailable",
			message,
			options,
		);
		return unavailable;
	}

	/**
	 * Whether `code` is a code the client decides itself.
	 */
	static [DECIDES](code: string): code is ClientCode {
		const decided = CLIENT_CODES.some((member) => member === code);
		return decided;
	}

	/**
	 * The `code` of `error` when it carries the name brand of a transport
	 * error, before any check of the code's membership. `Engine` checks the
	 * membership against the codes the engine declares.
	 */
	static [BRANDED_CODE](error: unknown): string | undefined {
		if (
			!(error instanceof Error) ||
			error.name !== ClientTransportError.NAME
		) {
			return undefined;
		}

		const code: unknown = Reflect.get(error, "code");
		if (typeof code !== "string") {
			return undefined;
		}

		return code;
	}

	/**
	 * Whether `error` reports a lost connection: an `Error` with the name
	 * brand of a transport error whose code is `ConnectionClosed`, a code the
	 * engine declares.
	 */
	static isConnectionClosed(error: unknown): error is TransportError {
		const code = ClientTransportError[BRANDED_CODE](error);
		const closed = code === "ConnectionClosed";
		return closed;
	}
}
