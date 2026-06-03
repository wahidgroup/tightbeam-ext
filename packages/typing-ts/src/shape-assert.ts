/**
 * Assertion-style shape validators that throw {@link ValidationError}.
 */

import type { FieldDef, ShapeOf } from "./shape.js";
import { ValidationError } from "./errors/validation-error.js";
import { validateObject } from "./shape.js";

/**
 * Asserts that `value` conforms to a specified spec. Required fields must
 * be present and match the expected type; optional fields are
 * validated only when present. Extra fields are permitted.
 *
 * @throws ValidationError when one or more constraints are violated.
 */
export function assertShape<F extends Record<string, FieldDef>>(
	value: unknown,
	fields: F,
	message?: string,
): asserts value is ShapeOf<F> {
	const issues = validateObject(value, fields, false);
	if (issues.length > 0) {
		throw new ValidationError("SHAPE_MISMATCH", issues, message);
	}
}

/**
 * Like {@link assertShape} but additionally rejects any field not
 * declared in the spec. Strict mode is applied recursively to
 * nested object specs.
 *
 * @throws When one or more constraints are violated or extra field is present.
 */
export function assertStrictShape<F extends Record<string, FieldDef>>(
	value: unknown,
	fields: F,
	message?: string,
): asserts value is ShapeOf<F, true> {
	const issues = validateObject(value, fields, true);
	if (issues.length > 0) {
		throw new ValidationError("SHAPE_MISMATCH", issues, message);
	}
}

/**
 * Validates and returns the narrowed value.
 */
export function asShape<F extends Record<string, FieldDef>>(
	value: unknown,
	fields: F,
	message?: string,
): ShapeOf<F> {
	assertShape(value, fields, message);
	return value;
}

/**
 * Strict variant of {@link asShape}. Rejects extra fields.
 */
export function asStrictShape<F extends Record<string, FieldDef>>(
	value: unknown,
	fields: F,
	message?: string,
): ShapeOf<F, true> {
	assertStrictShape(value, fields, message);
	return value;
}
