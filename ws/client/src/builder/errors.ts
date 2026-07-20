/**
 * Validation error surface for the frame builder.
 */

/**
 * A single validation issue with a field path and message.
 */
export interface ValidationIssue {
	readonly path: string;
	readonly message: string;
}

/**
 * Builds the default validation failure message.
 */
function validationMessage(issueCount: number): string {
	let label = "issues";
	if (issueCount === 1) {
		label = "issue";
	}

	return `Validation failed (${issueCount} ${label})`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function isValidationIssue(value: unknown): value is ValidationIssue {
	if (!isRecord(value)) {
		return false;
	}

	return typeof value.path === "string" && typeof value.message === "string";
}

/**
 * Represents one or more validation failures.
 *
 * Each failure is captured as a {@link ValidationIssue} with a
 * field path and descriptive message.
 */
export class ValidationError extends Error {
	readonly kind = "E_VALIDATION";
	readonly issues: readonly ValidationIssue[];

	constructor(
		readonly code: string,
		issues: readonly ValidationIssue[],
		message?: string,
		cause?: unknown,
	) {
		super(message ?? validationMessage(issues.length), { cause });
		this.name = this.constructor.name;
		this.issues = issues;
	}

	/**
	 * Duck-type guard for `ValidationError` instances; survives multiple
	 * copies of this module in one graph where `instanceof` would not.
	 */
	static isInstance(err: unknown): err is ValidationError {
		if (!isRecord(err)) {
			return false;
		}
		if (err.kind !== "E_VALIDATION") {
			return false;
		}
		if (typeof err.code !== "string" || typeof err.message !== "string") {
			return false;
		}

		return Array.isArray(err.issues) && err.issues.every(isValidationIssue);
	}
}
