/**
 * Error class for validation failures carrying structured issues.
 */

import type { ValidationIssue } from "./validation-issue.js";
import { CodedError } from "./coded-error.js";
import { ISSUES_FIELD_SPEC, validationMessage } from "./validation-issue.js";

/**
 * Represents one or more validation failures.
 *
 * Each failure is captured as a {@link ValidationIssue} with a
 * field path and descriptive message.
 */
export class ValidationError extends CodedError {
	readonly kind = "E_VALIDATION";
	readonly issues: readonly ValidationIssue[];

	constructor(
		readonly code: string,
		issues: readonly ValidationIssue[],
		message?: string,
		cause?: unknown,
	) {
		const derived = message ?? validationMessage(issues.length);
		super(derived, cause);
		this.issues = issues;
	}

	/**
	 * Duck-type guard for `ValidationError` instances.
	 */
	static override isInstance(err: unknown): err is ValidationError {
		return CodedError.isInstance(err, "E_VALIDATION", ISSUES_FIELD_SPEC);
	}

	/**
	 * Extends the base JSON with the `issues` list.
	 */
	override toJSON(): Record<string, unknown> {
		const json = { ...super.toJSON(), issues: this.issues };
		return json;
	}
}
