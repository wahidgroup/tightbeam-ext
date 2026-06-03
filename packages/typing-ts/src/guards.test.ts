import { describe, expect, it } from "vitest";

import {
	assertNever,
	hasProperties,
	isArray,
	isBoolean,
	isDefined,
	isError,
	isNonNull,
	isNumber,
	isOneOf,
	isRecord,
	isString,
	isSystemError,
} from "./guards.js";

// ---------------------------------------------------------------------------
// isRecord
// ---------------------------------------------------------------------------

describe("isRecord", () => {
	const truthy = [
		{ name: "plain object", value: {} },
		{ name: "object with keys", value: { a: 1 } },
		{ name: "Object.create(null)", value: Object.create(null) },
	];

	it.each(truthy)("returns true for $name", ({ value }) => {
		expect(isRecord(value)).toBe(true);
	});

	const falsy = [
		{ name: "null", value: null },
		{ name: "undefined", value: undefined },
		{ name: "string", value: "hello" },
		{ name: "number", value: 42 },
		{ name: "boolean", value: true },
		{ name: "array", value: [1, 2, 3] },
		{ name: "empty array", value: [] },
	];

	it.each(falsy)("returns false for $name", ({ value }) => {
		expect(isRecord(value)).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// hasProperties
// ---------------------------------------------------------------------------

describe("hasProperties", () => {
	it.each([
		{
			name: "all keys present",
			value: { a: 1, b: 2 },
			keys: ["a", "b"],
			expected: true,
		},
		{
			name: "extra keys allowed",
			value: { a: 1, b: 2, c: 3 },
			keys: ["a"],
			expected: true,
		},
		{
			name: "missing key",
			value: { a: 1 },
			keys: ["a", "b"],
			expected: false,
		},
		{ name: "null", value: null, keys: ["a"], expected: false },
		{ name: "string", value: "str", keys: ["length"], expected: false },
	])("returns $expected for $name", ({ value, keys, expected }) => {
		expect(hasProperties(value, ...keys)).toBe(expected);
	});
});

// ---------------------------------------------------------------------------
// Primitive guards
// ---------------------------------------------------------------------------

describe("isString", () => {
	it.each([
		{ value: "", expected: true },
		{ value: "hello", expected: true },
		{ value: 42, expected: false },
		{ value: null, expected: false },
		{ value: undefined, expected: false },
	])("returns $expected for $value", ({ value, expected }) => {
		expect(isString(value)).toBe(expected);
	});
});

describe("isNumber", () => {
	it.each([
		{ value: 0, expected: true },
		{ value: NaN, expected: true },
		{ value: Infinity, expected: true },
		{ value: "42", expected: false },
		{ value: null, expected: false },
	])("returns $expected for $value", ({ value, expected }) => {
		expect(isNumber(value)).toBe(expected);
	});
});

describe("isBoolean", () => {
	it.each([
		{ value: true, expected: true },
		{ value: false, expected: true },
		{ value: 0, expected: false },
		{ value: "", expected: false },
		{ value: null, expected: false },
	])("returns $expected for $value", ({ value, expected }) => {
		expect(isBoolean(value)).toBe(expected);
	});
});

// ---------------------------------------------------------------------------
// Nullability guards
// ---------------------------------------------------------------------------

describe("isNonNull", () => {
	it.each([
		{ name: "string", value: "hello", expected: true },
		{ name: "zero", value: 0, expected: true },
		{ name: "empty string", value: "", expected: true },
		{ name: "false", value: false, expected: true },
		{ name: "null", value: null, expected: false },
		{ name: "undefined", value: undefined, expected: false },
	])("returns $expected for $name", ({ value, expected }) => {
		expect(isNonNull(value)).toBe(expected);
	});
});

describe("isDefined", () => {
	it.each([
		{ name: "string", value: "hello", expected: true },
		{ name: "null", value: null, expected: true },
		{ name: "zero", value: 0, expected: true },
		{ name: "false", value: false, expected: true },
		{ name: "undefined", value: undefined, expected: false },
	])("returns $expected for $name", ({ value, expected }) => {
		expect(isDefined(value)).toBe(expected);
	});
});

// ---------------------------------------------------------------------------
// Collection / instance guards
// ---------------------------------------------------------------------------

describe("isArray", () => {
	it.each([
		{ name: "empty array", value: [], expected: true },
		{ name: "filled array", value: [1, 2], expected: true },
		{ name: "object", value: {}, expected: false },
		{ name: "string", value: "abc", expected: false },
		{ name: "null", value: null, expected: false },
	])("returns $expected for $name", ({ value, expected }) => {
		expect(isArray(value)).toBe(expected);
	});
});

describe("isError", () => {
	it.each([
		{ name: "Error", value: new Error("e"), expected: true },
		{ name: "TypeError", value: new TypeError("t"), expected: true },
		{ name: "string", value: "error", expected: false },
		{ name: "object", value: { message: "e" }, expected: false },
		{ name: "null", value: null, expected: false },
	])("returns $expected for $name", ({ value, expected }) => {
		expect(isError(value)).toBe(expected);
	});
});

// ---------------------------------------------------------------------------
// isOneOf
// ---------------------------------------------------------------------------

describe("isOneOf", () => {
	const statuses = ["active", "inactive", "pending"] as const;

	it("returns true for a matching string literal", () => {
		expect(isOneOf("active", statuses)).toBe(true);
	});

	it("returns false for a non-matching string", () => {
		expect(isOneOf("deleted", statuses)).toBe(false);
	});

	it("works with number literals", () => {
		const codes = [200, 404, 500] as const;
		expect(isOneOf(200, codes)).toBe(true);
		expect(isOneOf(403, codes)).toBe(false);
	});

	it("works with boolean literals", () => {
		const flags = [true] as const;
		expect(isOneOf(true, flags)).toBe(true);
		expect(isOneOf(false, flags)).toBe(false);
	});

	it("returns false for wrong types", () => {
		expect(isOneOf(null, statuses)).toBe(false);
		expect(isOneOf(42, statuses)).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// isSystemError
// ---------------------------------------------------------------------------

describe("isSystemError", () => {
	it("returns true for an Error with a matching code", () => {
		const err = Object.assign(new Error("not found"), { code: "ENOENT" });
		expect(isSystemError(err, "ENOENT")).toBe(true);
	});

	it("returns false for a non-matching code", () => {
		const err = Object.assign(new Error("denied"), { code: "EACCES" });
		expect(isSystemError(err, "ENOENT")).toBe(false);
	});

	it("returns false for a plain Error without code", () => {
		expect(isSystemError(new Error("plain"), "ENOENT")).toBe(false);
	});

	it("returns false for non-Error values", () => {
		expect(isSystemError({ code: "ENOENT" }, "ENOENT")).toBe(false);
		expect(isSystemError("ENOENT", "ENOENT")).toBe(false);
		expect(isSystemError(null, "ENOENT")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// assertNever
// ---------------------------------------------------------------------------

describe("assertNever", () => {
	it("throws a TypeError at runtime", () => {
		// @ts-expect-error assertNever rejects non-never values at compile time
		expect(() => assertNever("oops")).toThrow(TypeError);
	});

	it("includes the unexpected value in the message", () => {
		// @ts-expect-error assertNever rejects non-never values at compile time
		expect(() => assertNever(42)).toThrow("Unexpected value: 42");
	});
});
