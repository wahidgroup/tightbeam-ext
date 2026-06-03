/**
 * Error class for internal system errors not safe to display.
 */

import { CodedError } from "./coded-error.js";

/**
 * Represents internal system errors.
 *
 * Not safe to display to end users. Intended for logging, monitoring, and
 * developer diagnostics.
 */
export class InternalError extends CodedError {
	readonly kind = "E_INTERNAL";

	constructor(
		readonly code: string,
		message: string,
		cause?: unknown,
	) {
		super(message, cause);
	}

	/**
	 * Duck-type guard for `InternalError` instances.
	 */
	static override isInstance(err: unknown): err is InternalError {
		return CodedError.isInstance(err, "E_INTERNAL");
	}
}
