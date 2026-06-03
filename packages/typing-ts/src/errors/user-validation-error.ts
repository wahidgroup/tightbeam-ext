/**
 * User-facing validation error with automatic redaction of
 * sensitive values.
 */

import type { ValidationIssue } from "./validation-issue.js";
import { CodedError } from "./coded-error.js";
import { UserError } from "./user-error.js";
import { ISSUES_FIELD_SPEC, validationMessage } from "./validation-issue.js";

/**
 * Redaction placeholder used to replace sensitive values.
 */
const REDACTED = "****";

/**
 * Replaces every occurrence of each sensitive value in `text`.
 */
function redact(text: string, sensitive: readonly string[]): string {
	let result = text;
	for (const value of sensitive) {
		if (value.length === 0) {
			continue;
		}

		result = result.replaceAll(value, REDACTED);
	}

	return result;
}

/**
 * Represents user-facing validation failures safe to display.
 *
 * Extends {@link UserError} so the error is safe for end-user presentation.
 */
export class UserValidationError extends UserError {
	readonly issues: readonly ValidationIssue[];

	constructor(
		code: string,
		issues: readonly ValidationIssue[],
		sensitive?: readonly string[],
		message?: string,
		cause?: unknown,
	) {
		const shouldRedact = sensitive && sensitive.length > 0;

		let redacted: readonly ValidationIssue[];
		if (shouldRedact) {
			redacted = issues.map((issue) => ({
				path: issue.path,
				message: redact(issue.message, sensitive),
			}));
		} else {
			redacted = issues;
		}

		let derived: string;
		if (message && shouldRedact) {
			derived = redact(message, sensitive);
		} else if (message) {
			derived = message;
		} else {
			derived = validationMessage(issues.length);
		}

		super(code, derived, cause);
		this.issues = redacted;
	}

	/**
	 * Duck-type guard for `UserValidationError` instances.
	 */
	static override isInstance(err: unknown): err is UserValidationError {
		return CodedError.isInstance(err, "E_USER", ISSUES_FIELD_SPEC);
	}

	/**
	 * Extends the base JSON with the `issues` list.
	 */
	override toJSON(): Record<string, unknown> {
		const json = { ...super.toJSON(), issues: this.issues };
		return json;
	}
}
