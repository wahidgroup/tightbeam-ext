/**
 * Shared types and helpers for validation errors.
 */

import type { FieldDef } from "../shape.js";

/**
 * A single validation issue with a field path and message.
 */
export interface ValidationIssue {
	readonly path: string;
	readonly message: string;
}

/**
 * Shared `FieldDef` for duck-type checking the `issues` property
 * on validation error instances.
 */
export const ISSUES_FIELD_SPEC: Record<string, FieldDef> = {
	issues: {
		type: "array",
		items: {
			type: "object",
			shape: { path: "string", message: "string" },
		},
	},
};

/**
 * Builds the default validation failure message.
 */
export function validationMessage(issueCount: number): string {
	const label = issueCount === 1 ? "issue" : "issues";
	const message = `Validation failed (${issueCount} ${label})`;
	return message;
}
