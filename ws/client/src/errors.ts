/**
 * Error surface for the browser client.
 */

/**
 * Represents internal client errors, such as protocol violations by the
 * peer. Not safe to display to end users.
 */
export class InternalError extends Error {
	readonly kind = "E_INTERNAL";

	constructor(
		readonly code: string,
		message: string,
		cause?: unknown,
	) {
		super(message, { cause });
		this.name = this.constructor.name;
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

	constructor(
		readonly code: TransitCode,
		message: string,
	) {
		super(message);
	}
}

/**
 * The `name` carried by every structured transport error thrown from the
 * wasm layer.
 */
export const TRANSPORT_ERROR_NAME = "TightbeamTransportError";

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
	/** The tightbeam-rs error variant name. */
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
