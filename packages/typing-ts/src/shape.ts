/**
 * Spec-driven shape validation with type-level inference.
 */

import type { ValidationIssue } from "./errors/validation-issue.js";
import { isRecord } from "./guards.js";

// ---------------------------------------------------------------------------
// Field spec types
// ---------------------------------------------------------------------------

/**
 * Allowed primitive type names for field validation.
 */
export type PrimitiveType = "string" | "number" | "boolean";

/**
 * Maps a primitive type name to the corresponding TypeScript type.
 */
type PrimitiveMap = {
	string: string;
	number: number;
	boolean: boolean;
};

/**
 * A field whose value must match a primitive `typeof` check.
 */
export interface PrimitiveFieldSpec {
	readonly type: PrimitiveType;
	readonly optional?: boolean;
}

/**
 * A field whose value must be an array with every element
 * matching the `items` spec.
 */
export interface ArrayFieldSpec {
	readonly type: "array";
	readonly items: FieldDef;
	readonly optional?: boolean;
}

/**
 * A field whose value must be a plain object matching the
 * nested `shape` spec.
 */
export interface ObjectFieldSpec {
	readonly type: "object";
	readonly shape: Record<string, FieldDef>;
	readonly optional?: boolean;
}

/**
 * A field whose value must be one of a fixed set of literals.
 */
export interface LiteralFieldSpec {
	readonly type: "literal";
	readonly values: readonly (string | number | boolean)[];
	readonly optional?: boolean;
}

/**
 * Union of all structured field spec variants.
 */
export type FieldSpec =
	| PrimitiveFieldSpec
	| ArrayFieldSpec
	| ObjectFieldSpec
	| LiteralFieldSpec;

/**
 * A field definition: either a shorthand primitive type name
 * or a full spec object.
 */
export type FieldDef = PrimitiveType | FieldSpec;

// ---------------------------------------------------------------------------
// Type-level inference
// ---------------------------------------------------------------------------

/**
 * Infers the TypeScript type for a single `FieldDef`.
 */
type InferFieldDef<F extends FieldDef> = F extends PrimitiveType
	? PrimitiveMap[F]
	: F extends PrimitiveFieldSpec
		? PrimitiveMap[F["type"]]
		: F extends ArrayFieldSpec
			? InferFieldDef<F["items"]>[]
			: F extends ObjectFieldSpec
				? ShapeOf<F["shape"]>
				: F extends LiteralFieldSpec
					? F["values"][number]
					: never;

/**
 * Derives a TypeScript type from a field spec record.
 *
 * When `S` is `false` (the default) the result is intersected with
 * `Record<string, unknown>` so extra fields are permitted.
 * When `S` is `true` (strict mode) only declared fields are present.
 */
export type ShapeOf<
	F extends Record<string, FieldDef>,
	S extends boolean = false,
> = {
	[K in keyof F as IsOptional<F[K]> extends true ? never : K]: InferFieldDef<
		F[K]
	>;
} & {
	[K in keyof F as IsOptional<F[K]> extends true ? K : never]?: InferFieldDef<
		F[K]
	>;
} & (S extends true ? unknown : Record<string, unknown>);

/**
 * Determines whether a field def is marked optional.
 */
type IsOptional<F extends FieldDef> = F extends { optional: true }
	? true
	: false;

// ---------------------------------------------------------------------------
// Runtime helpers
// ---------------------------------------------------------------------------

/**
 * Normalizes a shorthand `FieldDef` to a full `FieldSpec`.
 */
function normalizeSpec(def: FieldDef): FieldSpec {
	if (typeof def === "string") {
		return { type: def };
	}

	return def;
}

/**
 * A queued field-level validation item.
 */
interface FieldWorkItem {
	readonly kind: "field";
	readonly value: unknown;
	readonly spec: FieldSpec;
	readonly path: string;
}

/**
 * A queued object-level validation item.
 */
interface ObjectWorkItem {
	readonly kind: "object";
	readonly value: unknown;
	readonly fields: Record<string, FieldDef>;
	readonly path: string;
}

/**
 * Discriminated union of work items for the validation stack.
 */
type WorkItem = FieldWorkItem | ObjectWorkItem;

/**
 * Iteratively validates a work item and all reachable children.
 * Collects every issue rather than bailing on the first failure.
 */
function validate(initial: WorkItem, strict: boolean): ValidationIssue[] {
	const issues: ValidationIssue[] = [];
	const stack: WorkItem[] = [initial];
	while (stack.length > 0) {
		const current = stack.pop();
		if (current === undefined) {
			break;
		}

		if (current.kind === "object") {
			if (!isRecord(current.value)) {
				const message = current.path
					? `Field ${current.path} must be an object`
					: "Expected an object";

				issues.push({ path: current.path, message });

				continue;
			}

			const entries = Object.entries(current.fields);
			for (let i = entries.length - 1; i >= 0; i--) {
				const entry = entries[i];
				if (entry === undefined) {
					continue;
				}

				const [key, def] = entry;
				const spec = normalizeSpec(def);
				const fieldPath = current.path ? `${current.path}.${key}` : key;

				if (!(key in current.value)) {
					if (!spec.optional) {
						issues.push({
							path: fieldPath,
							message: `Missing required field: ${fieldPath}`,
						});
					}

					continue;
				}

				const fieldValue: unknown = Reflect.get(current.value, key);
				stack.push({
					kind: "field",
					value: fieldValue,
					spec,
					path: fieldPath,
				});
			}

			if (strict) {
				for (const key of Object.keys(current.value)) {
					if (!(key in current.fields)) {
						const fieldPath = current.path
							? `${current.path}.${key}`
							: key;
						issues.push({
							path: fieldPath,
							message: `Unexpected field: ${fieldPath}`,
						});
					}
				}
			}

			continue;
		}

		if (
			current.spec.type === "string" ||
			current.spec.type === "number" ||
			current.spec.type === "boolean"
		) {
			if (typeof current.value !== current.spec.type) {
				issues.push({
					path: current.path,
					message: `Field ${current.path} must be ${current.spec.type}, got ${typeof current.value}`,
				});
			}

			continue;
		}

		if (current.spec.type === "array") {
			if (!Array.isArray(current.value)) {
				issues.push({
					path: current.path,
					message: `Field ${current.path} must be an array`,
				});
				continue;
			}

			const itemSpec = normalizeSpec(current.spec.items);
			for (let i = current.value.length - 1; i >= 0; i--) {
				stack.push({
					kind: "field",
					value: current.value[i],
					spec: itemSpec,
					path: `${current.path}[${i}]`,
				});
			}

			continue;
		}

		if (current.spec.type === "object") {
			stack.push({
				kind: "object",
				value: current.value,
				fields: current.spec.shape,
				path: current.path,
			});
			continue;
		}

		if (current.spec.type === "literal") {
			let matched = false;
			for (const allowed of current.spec.values) {
				if (current.value === allowed) {
					matched = true;
					break;
				}
			}

			if (!matched) {
				issues.push({
					path: current.path,
					message: `Field ${current.path} must be one of [${current.spec.values.join(", ")}], got ${String(current.value)}`,
				});
			}

			continue;
		}

		issues.push({
			path: current.path,
			message: `Unknown field spec type at ${current.path}`,
		});
	}

	return issues;
}

/**
 * Validates a value against an object shape spec.
 * Returns a list of all validation issues (empty when valid).
 */
export function validateObject(
	value: unknown,
	fields: Record<string, FieldDef>,
	strict: boolean,
	prefix?: string,
): ValidationIssue[] {
	const initial: ObjectWorkItem = {
		kind: "object",
		value,
		fields,
		path: prefix ?? "",
	};
	return validate(initial, strict);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Predicate guard: returns `true` when `value` conforms to the spec.
 *
 * Extra fields beyond the spec are permitted.
 */
export function isShape<F extends Record<string, FieldDef>>(
	value: unknown,
	fields: F,
): value is ShapeOf<F> {
	const issues = validateObject(value, fields, false);
	return issues.length === 0;
}
