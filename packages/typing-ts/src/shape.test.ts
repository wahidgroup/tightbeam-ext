import { describe, expect, it } from "vitest";

import type { FieldDef } from "./shape.js";
import { ValidationError } from "./errors/validation-error.js";
import {
	asShape,
	asStrictShape,
	assertShape,
	assertStrictShape,
} from "./shape-assert.js";
import { isShape, validateObject } from "./shape.js";

// ---------------------------------------------------------------------------
// Shared specs
// ---------------------------------------------------------------------------

const primitiveSpec: Record<string, FieldDef> = {
	name: "string",
	age: "number",
};

const optionalSpec: Record<string, FieldDef> = {
	name: "string",
	age: { type: "number", optional: true },
};

const arraySpec: Record<string, FieldDef> = {
	tags: { type: "array", items: "string" },
};

const nestedSpec: Record<string, FieldDef> = {
	address: { type: "object", shape: { city: "string", zip: "string" } },
};

const literalSpec: Record<string, FieldDef> = {
	status: { type: "literal", values: ["active", "inactive"] },
};

const mixedSpec: Record<string, FieldDef> = {
	name: "string",
	age: { type: "number", optional: true },
	tags: { type: "array", items: "string" },
	address: { type: "object", shape: { city: "string" } },
	role: { type: "literal", values: ["admin", "user"] },
};

const arrayOfObjectsSpec: Record<string, FieldDef> = {
	items: {
		type: "array",
		items: { type: "object", shape: { name: "string" } },
	},
};

const arrayOfLiteralsSpec: Record<string, FieldDef> = {
	roles: {
		type: "array",
		items: { type: "literal", values: ["admin", "user"] },
	},
};

const deepSpec: Record<string, FieldDef> = {
	level1: {
		type: "object",
		shape: {
			level2: { type: "object", shape: { value: "number" } },
		},
	},
};

const optionalArraySpec: Record<string, FieldDef> = {
	tags: { type: "array", items: "string", optional: true },
};

const optionalNestedSpec: Record<string, FieldDef> = {
	meta: { type: "object", shape: { key: "string" }, optional: true },
};

// ---------------------------------------------------------------------------
// isShape - predicate guard
// ---------------------------------------------------------------------------

describe("isShape", () => {
	interface ShapeCase {
		name: string;
		spec: Record<string, FieldDef>;
		value: unknown;
		expected: boolean;
	}

	const cases: ShapeCase[] = [
		// primitive fields
		{
			name: "primitive: matching object",
			spec: primitiveSpec,
			value: { name: "Alice", age: 30 },
			expected: true,
		},
		{
			name: "primitive: extra fields allowed",
			spec: primitiveSpec,
			value: { name: "Bob", age: 25, extra: true },
			expected: true,
		},
		{
			name: "primitive: null",
			spec: primitiveSpec,
			value: null,
			expected: false,
		},
		{
			name: "primitive: undefined",
			spec: primitiveSpec,
			value: undefined,
			expected: false,
		},
		{
			name: "primitive: string",
			spec: primitiveSpec,
			value: "hello",
			expected: false,
		},
		{
			name: "primitive: array",
			spec: primitiveSpec,
			value: [1, 2],
			expected: false,
		},
		{
			name: "primitive: missing field",
			spec: primitiveSpec,
			value: { name: "Alice" },
			expected: false,
		},
		{
			name: "primitive: wrong type",
			spec: primitiveSpec,
			value: { name: 123, age: 30 },
			expected: false,
		},
		// optional fields
		{
			name: "optional: field absent",
			spec: optionalSpec,
			value: { name: "Alice" },
			expected: true,
		},
		{
			name: "optional: field present and correct",
			spec: optionalSpec,
			value: { name: "Alice", age: 30 },
			expected: true,
		},
		{
			name: "optional: field wrong type",
			spec: optionalSpec,
			value: { name: "Alice", age: "thirty" },
			expected: false,
		},
		// array fields
		{
			name: "array: valid elements",
			spec: arraySpec,
			value: { tags: ["a", "b"] },
			expected: true,
		},
		{
			name: "array: empty",
			spec: arraySpec,
			value: { tags: [] },
			expected: true,
		},
		{
			name: "array: non-array value",
			spec: arraySpec,
			value: { tags: "not-array" },
			expected: false,
		},
		{
			name: "array: wrong element type",
			spec: arraySpec,
			value: { tags: ["a", 42] },
			expected: false,
		},
		// nested object fields
		{
			name: "nested: valid object",
			spec: nestedSpec,
			value: { address: { city: "NYC", zip: "10001" } },
			expected: true,
		},
		{
			name: "nested: missing field",
			spec: nestedSpec,
			value: { address: { city: "NYC" } },
			expected: false,
		},
		{
			name: "nested: wrong field type",
			spec: nestedSpec,
			value: { address: { city: "NYC", zip: 10001 } },
			expected: false,
		},
		{
			name: "nested: not an object",
			spec: nestedSpec,
			value: { address: "NYC" },
			expected: false,
		},
		// literal fields
		{
			name: "literal: matching active",
			spec: literalSpec,
			value: { status: "active" },
			expected: true,
		},
		{
			name: "literal: matching inactive",
			spec: literalSpec,
			value: { status: "inactive" },
			expected: true,
		},
		{
			name: "literal: non-matching value",
			spec: literalSpec,
			value: { status: "deleted" },
			expected: false,
		},
		{
			name: "literal: wrong type",
			spec: literalSpec,
			value: { status: 42 },
			expected: false,
		},
		// mixed spec
		{
			name: "mixed: complete valid payload",
			spec: mixedSpec,
			value: {
				name: "Alice",
				age: 30,
				tags: ["dev"],
				address: { city: "NYC" },
				role: "admin",
			},
			expected: true,
		},
		{
			name: "mixed: optional field omitted",
			spec: mixedSpec,
			value: {
				name: "Bob",
				tags: [],
				address: { city: "LA" },
				role: "user",
			},
			expected: true,
		},
		// edge: nested arrays of objects
		{
			name: "edge: array of objects valid",
			spec: arrayOfObjectsSpec,
			value: { items: [{ name: "a" }, { name: "b" }] },
			expected: true,
		},
		{
			name: "edge: array of objects invalid element",
			spec: arrayOfObjectsSpec,
			value: { items: [{ name: "a" }, { wrong: "b" }] },
			expected: false,
		},
		// edge: arrays of literal values
		{
			name: "edge: array of literals valid",
			spec: arrayOfLiteralsSpec,
			value: { roles: ["admin", "user"] },
			expected: true,
		},
		{
			name: "edge: array of literals invalid",
			spec: arrayOfLiteralsSpec,
			value: { roles: ["admin", "guest"] },
			expected: false,
		},
		// edge: deeply nested objects
		{
			name: "edge: deep nested valid",
			spec: deepSpec,
			value: { level1: { level2: { value: 42 } } },
			expected: true,
		},
		{
			name: "edge: deep nested invalid",
			spec: deepSpec,
			value: { level1: { level2: { value: "no" } } },
			expected: false,
		},
		// edge: optional array field
		{
			name: "edge: optional array omitted",
			spec: optionalArraySpec,
			value: {},
			expected: true,
		},
		{
			name: "edge: optional array present",
			spec: optionalArraySpec,
			value: { tags: ["a"] },
			expected: true,
		},
		{
			name: "edge: optional array wrong element",
			spec: optionalArraySpec,
			value: { tags: [42] },
			expected: false,
		},
		// edge: optional nested object field
		{
			name: "edge: optional nested omitted",
			spec: optionalNestedSpec,
			value: {},
			expected: true,
		},
		{
			name: "edge: optional nested present",
			spec: optionalNestedSpec,
			value: { meta: { key: "v" } },
			expected: true,
		},
		{
			name: "edge: optional nested wrong type",
			spec: optionalNestedSpec,
			value: { meta: { key: 42 } },
			expected: false,
		},
	];

	it.each(cases)("$name", ({ value, spec, expected }) => {
		expect(isShape(value, spec)).toBe(expected);
	});
});

// ---------------------------------------------------------------------------
// assertShape / assertStrictShape - throw behavior
// ---------------------------------------------------------------------------

describe("assert-family", () => {
	type AssertFn = (
		value: unknown,
		fields: Record<string, FieldDef>,
		message?: string,
	) => void;

	const shape: AssertFn = (value, fields, message) => {
		assertShape(value, fields, message);
	};

	const strict: AssertFn = (value, fields, message) => {
		assertStrictShape(value, fields, message);
	};

	const nestedStrictSpec: Record<string, FieldDef> = {
		inner: { type: "object", shape: { a: "string" } },
	};

	interface AssertCase {
		name: string;
		fn: AssertFn;
		value: unknown;
		spec: Record<string, FieldDef>;
		message?: string;
		throws: boolean;
	}

	const cases: AssertCase[] = [
		{
			name: "assertShape: valid shape",
			fn: shape,
			value: { name: "x", count: 1 },
			spec: { name: "string", count: "number" },
			throws: false,
		},
		{
			name: "assertShape: null",
			fn: shape,
			value: null,
			spec: { name: "string", count: "number" },
			throws: true,
		},
		{
			name: "assertShape: missing field",
			fn: shape,
			value: { name: "x" },
			spec: { name: "string", count: "number" },
			throws: true,
		},
		{
			name: "assertShape: custom message",
			fn: shape,
			value: null,
			spec: { name: "string" },
			message: "bad input",
			throws: true,
		},
		{
			name: "assertStrictShape: only declared fields",
			fn: strict,
			value: { name: "x" },
			spec: { name: "string" },
			throws: false,
		},
		{
			name: "assertStrictShape: extra fields",
			fn: strict,
			value: { name: "x", extra: true },
			spec: { name: "string" },
			throws: true,
		},
		{
			name: "assertStrictShape: nested extras",
			fn: strict,
			value: { inner: { a: "x", b: "y" } },
			spec: nestedStrictSpec,
			throws: true,
		},
		{
			name: "assertStrictShape: custom message",
			fn: strict,
			value: { name: "x", extra: 1 },
			spec: { name: "string" },
			message: "strict",
			throws: true,
		},
	];

	it.each(cases)("$name", ({ fn, value, spec, message, throws }) => {
		const invoke = () => fn(value, spec, message);

		if (!throws) {
			expect(invoke).not.toThrow();
			return;
		}

		if (message !== undefined) {
			expect(invoke).toThrow(message);
			return;
		}

		expect(invoke).toThrow(ValidationError);
	});
});

// ---------------------------------------------------------------------------
// asShape / asStrictShape - narrowing convenience
// ---------------------------------------------------------------------------

describe("as-family", () => {
	type AsFn = (value: unknown, fields: Record<string, FieldDef>) => unknown;

	const shape: AsFn = (value, fields) => asShape(value, fields);

	const strict: AsFn = (value, fields) => asStrictShape(value, fields);

	const spec: Record<string, FieldDef> = { id: "number" };

	interface AsCase {
		name: string;
		fn: AsFn;
		value: unknown;
		throws: boolean;
	}

	const cases: AsCase[] = [
		{
			name: "asShape: returns narrowed value",
			fn: shape,
			value: { id: 1, extra: true },
			throws: false,
		},
		{
			name: "asShape: throws on failure",
			fn: shape,
			value: null,
			throws: true,
		},
		{
			name: "asStrictShape: returns narrowed value",
			fn: strict,
			value: { id: 1 },
			throws: false,
		},
		{
			name: "asStrictShape: throws on extra fields",
			fn: strict,
			value: { id: 1, extra: true },
			throws: true,
		},
	];

	it.each(cases)("$name", ({ fn, value, throws }) => {
		if (throws) {
			expect(() => fn(value, spec)).toThrow(ValidationError);
			return;
		}

		expect(fn(value, spec)).toEqual(value);
	});
});

// ---------------------------------------------------------------------------
// validateObject - issue collection
// ---------------------------------------------------------------------------

describe("validateObject", () => {
	interface ValidateCase {
		name: string;
		value: unknown;
		spec: Record<string, FieldDef>;
		strict: boolean;
		prefix?: string;
		expectedPaths: string[];
	}

	const cases: ValidateCase[] = [
		{
			name: "valid input yields no issues",
			value: { name: "Alice", age: 30 },
			spec: { name: "string", age: "number" },
			strict: false,
			expectedPaths: [],
		},
		{
			name: "collects issues from multiple wrong types",
			value: { name: 42, age: "old", active: "yes" },
			spec: { name: "string", age: "number", active: "boolean" },
			strict: false,
			expectedPaths: ["name", "age", "active"],
		},
		{
			name: "reports missing required fields",
			value: {},
			spec: { a: "string", b: "number" },
			strict: false,
			expectedPaths: ["a", "b"],
		},
		{
			name: "nested fields use dot notation",
			value: { address: { city: 42, zip: "bad" } },
			spec: {
				address: {
					type: "object",
					shape: { city: "string", zip: "number" },
				},
			},
			strict: false,
			expectedPaths: ["address.city", "address.zip"],
		},
		{
			name: "array elements use bracket notation",
			value: { tags: ["ok", 42, true] },
			spec: { tags: { type: "array", items: "string" } },
			strict: false,
			expectedPaths: ["tags[1]", "tags[2]"],
		},
		{
			name: "strict mode reports unexpected fields",
			value: { name: "Alice", extra: true, bonus: 1 },
			spec: { name: "string" },
			strict: true,
			expectedPaths: ["extra", "bonus"],
		},
		{
			name: "non-object root yields empty-path issue",
			value: null,
			spec: { name: "string" },
			strict: false,
			expectedPaths: [""],
		},
		{
			name: "prefix prepends to issue paths",
			value: {},
			spec: { x: "string" },
			strict: false,
			prefix: "root",
			expectedPaths: ["root.x"],
		},
	];

	it.each(cases)(
		"$name",
		({ value, spec, strict, prefix, expectedPaths }) => {
			const issues = validateObject(value, spec, strict, prefix);
			expect(issues).toHaveLength(expectedPaths.length);

			const paths = issues.map((i) => i.path);
			for (const expected of expectedPaths) {
				expect(paths).toContain(expected);
			}
		},
	);
});
