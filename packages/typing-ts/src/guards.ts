/**
 * Runtime type guards for narrowing `unknown` values.
 */

// ---------------------------------------------------------------------------
// Primitive guards
// ---------------------------------------------------------------------------

/**
 * Narrows an unknown value to `string`.
 */
export function isString(value: unknown): value is string {
	return typeof value === "string";
}

/**
 * Narrows an unknown value to `number`.
 */
export function isNumber(value: unknown): value is number {
	return typeof value === "number";
}

/**
 * Narrows an unknown value to `boolean`.
 */
export function isBoolean(value: unknown): value is boolean {
	return typeof value === "boolean";
}

// ---------------------------------------------------------------------------
// Nullability guards
// ---------------------------------------------------------------------------

/**
 * Excludes both `null` and `undefined` from `T`.
 */
export function isNonNull<T>(value: T): value is NonNullable<T> {
	return value !== null && value !== undefined;
}

/**
 * Excludes `undefined` from `T` (allows `null`).
 */
export function isDefined<T>(value: T): value is Exclude<T, undefined> {
	return value !== undefined;
}

// ---------------------------------------------------------------------------
// Collection / instance guards
// ---------------------------------------------------------------------------

/**
 * Narrows an unknown value to `unknown[]`.
 */
export function isArray(value: unknown): value is unknown[] {
	return Array.isArray(value);
}

/**
 * Narrows an unknown value to `Error`.
 */
export function isError(value: unknown): value is Error {
	return value instanceof Error;
}

// ---------------------------------------------------------------------------
// Object guards
// ---------------------------------------------------------------------------

/**
 * Narrows an unknown value to a non-null object (includes arrays).
 */
function isObject(value: unknown): value is object {
	return typeof value === "object" && value !== null;
}

/**
 * Narrows an unknown value to a string-keyed record.
 *
 * Returns `false` for `null`, primitives, and arrays.
 */
export function isRecord(value: unknown): value is Record<string, unknown> {
	return isObject(value) && !isArray(value);
}

/**
 * Duck-type guard that checks whether `value` is a non-null object
 * containing all of the specified keys.
 */
export function hasProperties<K extends string>(
	value: unknown,
	...keys: K[]
): value is Record<K, unknown> {
	if (!isRecord(value)) {
		return false;
	}

	for (const key of keys) {
		if (!(key in value)) {
			return false;
		}
	}

	return true;
}

// ---------------------------------------------------------------------------
// Narrowing helpers
// ---------------------------------------------------------------------------

/**
 * Narrows `value` to a member of a readonly literal tuple.
 */
export function isOneOf<T extends string | number | boolean>(
	value: unknown,
	values: readonly T[],
): value is T {
	for (const candidate of values) {
		if (value === candidate) {
			return true;
		}
	}

	return false;
}

/**
 * Checks whether `err` is an `Error` with a `code` property matching
 * the given string. Covers Node.js system error codes such as
 * `ENOENT`, `EACCES`, `EPERM`, `ECONNREFUSED`, etc.
 */
export function isSystemError(err: unknown, code: string): boolean {
	if (!(err instanceof Error) || !("code" in err)) {
		return false;
	}

	const errCode: unknown = Reflect.get(err, "code");
	return errCode === code;
}

// ---------------------------------------------------------------------------
// Exhaustive check
// ---------------------------------------------------------------------------

/**
 * Enforces exhaustive `switch`/`if` checks at compile time.
 * Throws at runtime if reached.
 */
export function assertNever(value: never): never {
	throw new TypeError(`Unexpected value: ${String(value)}`);
}
