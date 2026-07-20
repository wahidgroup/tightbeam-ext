/**
 * Error surface for the browser client.
 */

/**
 * Represents internal client errors, such as protocol violations by the
 * peer. Not safe to display to end users; intended for logging and
 * developer diagnostics.
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
