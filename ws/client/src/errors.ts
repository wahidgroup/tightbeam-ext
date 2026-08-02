/**
 * Error surface for the browser client.
 */

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
	readonly code: string;

	constructor(code: string, message: string, cause?: unknown) {
		super(message, { cause });
		this.name = this.constructor.name;
		this.code = code;
	}
}

/**
 * The gRPC canonical status registry (`google.rpc.Code`) names a serve
 * handler may answer a stream with. Every code except `Ok`: a returned
 * frame or `undefined` already expresses acceptance.
 */
export type TransitCode =
	| "Cancelled"
	| "Unknown"
	| "InvalidArgument"
	| "DeadlineExceeded"
	| "NotFound"
	| "AlreadyExists"
	| "PermissionDenied"
	| "ResourceExhausted"
	| "FailedPrecondition"
	| "Aborted"
	| "OutOfRange"
	| "Unimplemented"
	| "Internal"
	| "Unavailable"
	| "DataLoss"
	| "Unauthenticated";

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
	readonly code: TransitCode;

	constructor(code: TransitCode, message: string) {
		super(message);
		this.code = code;
	}
}

/**
 * The `name` carried by every structured transport error thrown from the
 * wasm layer.
 */
export const TRANSPORT_ERROR_NAME = "TightbeamTransportError";

/**
 * A client-side {@link TransportError}: the shape the wasm layer throws,
 * for failures detected before a call crosses the boundary.
 */
class ClientTransportError extends Error implements TransportError {
	override readonly name: string = TRANSPORT_ERROR_NAME;

	/**
	 * The tightbeam-rs error variant name used for programmatic branching.
	 */
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.code = code;
	}
}

/**
 * The rejection for an operation on a released client: the same
 * `ConnectionClosed` code in-flight emits settle with when the
 * connection drops.
 */
export function connectionClosed(operation: string): TransportError {
	const failure = new ClientTransportError(
		"ConnectionClosed",
		`Cannot ${operation}: the client is closed and its wasm resources are released`,
	);

	return failure;
}

/**
 * A transport failure thrown from the wasm layer.
 *
 * `code` is the tightbeam-rs error variant name, machine-readable and
 * stable across releases. The codes callers most often branch on:
 *
 * - `ConnectionClosed`: the peer or network ended the connection.
 * - `Draining`: GoAway sent or received. No new streams.
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
	/**
	 * The tightbeam-rs error variant name.
	 *
	 * Callers branch on this string. The set is stable across releases for
	 * the codes listed on this interface.
	 */
	readonly code: string;
}

/**
 * Narrow an unknown rejection to a structured {@link TransportError}.
 */
export function isTransportError(error: unknown): error is TransportError {
	if (!(error instanceof Error) || error.name !== TRANSPORT_ERROR_NAME) {
		return false;
	}

	const code: unknown = Reflect.get(error, "code");
	const structured = typeof code === "string";
	return structured;
}
