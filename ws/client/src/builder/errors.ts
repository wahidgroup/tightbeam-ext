/**
 * Validation error surface for the frame builder.
 */

/**
 * A single validation issue with a field path and message.
 */
export interface ValidationIssue {
	/**
	 * Dot-separated path to the failing field (for example `metadata.id`).
	 */
	readonly path: string;
	/**
	 * Human-readable description of the validation failure at that path.
	 */
	readonly message: string;
}

/**
 * The code of a {@link ValidationError}: the rule of the TypeScript client
 * that the call breaks.
 *
 * - `FRAME_SPEC`: the accumulated builder spec is invalid, or the built frame carries another version than the spec asserted.
 * - `FRAME_CONFIDENTIAL`: a plain read of a sealed body.
 * - `FRAME_COMPRESSED`: a plain read of a compressed body.
 * - `FRAME_NOT_CONFIDENTIAL`: a decryption of a cleartext body.
 * - `MISSING_OPENER`: the frame is sealed and no `opener` is given.
 * - `MISSING_INFLATOR`: the frame is compressed and no `inflator` is given.
 * - `COMPACTNESS_REFUSED`: the inflator does not admit the compactness info.
 * - `ENVELOPE_SIGNER`: a signed envelope frames a message without a signer.
 * - `ENVELOPE_SEALER`: a sealed envelope frames a message without a sealer.
 * - `ENVELOPE_CLEARTEXT`: a sealed envelope unwraps a cleartext frame.
 * - `ENVELOPE_VERIFIER`: a signed envelope unwraps a frame without a verifier.
 * - `ENVELOPE_UNSIGNED`: a signed envelope unwraps an unsigned frame.
 */
export type ValidationCode =
	| "FRAME_SPEC"
	| "FRAME_CONFIDENTIAL"
	| "FRAME_COMPRESSED"
	| "FRAME_NOT_CONFIDENTIAL"
	| "MISSING_OPENER"
	| "MISSING_INFLATOR"
	| "COMPACTNESS_REFUSED"
	| "ENVELOPE_SIGNER"
	| "ENVELOPE_SEALER"
	| "ENVELOPE_CLEARTEXT"
	| "ENVELOPE_VERIFIER"
	| "ENVELOPE_UNSIGNED";

function isRecord(value: unknown): value is Record<string, unknown> {
	const record = typeof value === "object" && value !== null;
	return record;
}

/**
 * Represents one or more validation failures.
 *
 * Each failure is captured as a {@link ValidationIssue} with a
 * field path and descriptive message.
 */
export class ValidationError extends Error {
	/**
	 * Discriminant for the validation error family.
	 */
	readonly kind = "E_VALIDATION";

	/**
	 * Stable programmatic code for branching on this failure.
	 */
	readonly code: ValidationCode;

	/**
	 * Field-level issues that caused the failure, in encounter order.
	 */
	readonly issues: readonly ValidationIssue[];

	constructor(
		code: ValidationCode,
		issues: readonly ValidationIssue[],
		message?: string,
		cause?: unknown,
	) {
		super(message ?? ValidationError.defaultMessage(issues.length), {
			cause,
		});
		this.name = this.constructor.name;
		this.code = code;
		this.issues = issues;
	}

	/**
	 * Duck-type guard for `ValidationError` instances. Survives multiple
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

		const valid =
			Array.isArray(err.issues) &&
			err.issues.every((issue) => ValidationError.isIssue(issue));
		return valid;
	}

	/**
	 * The default message of a failure with `issueCount` issues.
	 */
	private static defaultMessage(issueCount: number): string {
		let label = "issues";
		if (issueCount === 1) {
			label = "issue";
		}

		const message = `Validation failed (${issueCount} ${label})`;
		return message;
	}

	/**
	 * Whether `value` has the shape of a {@link ValidationIssue}.
	 */
	private static isIssue(value: unknown): value is ValidationIssue {
		if (!isRecord(value)) {
			return false;
		}

		const valid =
			typeof value.path === "string" && typeof value.message === "string";
		return valid;
	}
}
