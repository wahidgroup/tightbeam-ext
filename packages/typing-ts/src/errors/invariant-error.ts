/**
 * Error class for data integrity violations.
 */

import { CodedError } from "./coded-error.js";

/**
 * Represents invariant violations - conditions that should
 * never occur if the system is functioning correctly.
 *
 * Signals a programming error or data corruption.
 */
export class InvariantError extends CodedError {
	readonly kind = "E_INVARIANT";

	constructor(
		readonly code: string,
		message: string,
		cause?: unknown,
	) {
		super(message, cause);
	}

	/**
	 * Duck-type guard for `InvariantError` instances.
	 */
	static override isInstance(err: unknown): err is InvariantError {
		return CodedError.isInstance(err, "E_INVARIANT");
	}
}
