/**
 * Error class for user-facing errors that are safe to display.
 */

import { CodedError } from "./coded-error.js";

/**
 * Represents errors caused by user input or actions.
 *
 * Safe to display in user-facing UI. Consumers pass bare codes
 * (e.g., `"VALIDATION_FAILED"`) without an `E_` prefix.
 */
export class UserError extends CodedError {
	readonly kind = "E_USER";

	constructor(
		readonly code: string,
		message: string,
		cause?: unknown,
	) {
		super(message, cause);
	}

	/**
	 * Duck-type guard for `UserError` instances.
	 */
	static override isInstance(err: unknown): err is UserError {
		return CodedError.isInstance(err, "E_USER");
	}
}
