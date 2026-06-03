import { describe, expect, it } from "vitest";

import type { ValidationIssue } from "./validation-issue.js";
import { ApiError } from "./api-error.js";
import { CodedError } from "./coded-error.js";
import { InternalError } from "./internal-error.js";
import { InvariantError } from "./invariant-error.js";
import { UserError } from "./user-error.js";
import { UserValidationError } from "./user-validation-error.js";
import { ValidationError } from "./validation-error.js";
import { errorMessage } from "./message.js";

// ---------------------------------------------------------------------------
// CodedError contract (shared across every concrete subclass)
// ---------------------------------------------------------------------------

describe("CodedError contract", () => {
	type ErrorCtor = abstract new (...args: never[]) => object;

	const internalCause = new Error("root cause");
	const userValidationCause = new Error("root");

	interface ContractCase {
		name: string;
		factory: () => CodedError;
		expectedName: string;
		kind: string;
		code: string;
		qualifiedCode: string;
		cause?: Error;
		extraInstances?: ErrorCtor[];
	}

	const cases: ContractCase[] = [
		{
			name: "UserError",
			factory: () => new UserError("VALIDATION_FAILED", "bad input"),
			expectedName: "UserError",
			kind: "E_USER",
			code: "VALIDATION_FAILED",
			qualifiedCode: "E_USER_VALIDATION_FAILED",
		},
		{
			name: "ApiError",
			factory: () => new ApiError("NOT_FOUND", 404, "Not found"),
			expectedName: "ApiError",
			kind: "E_API",
			code: "NOT_FOUND",
			qualifiedCode: "E_API_NOT_FOUND",
		},
		{
			name: "InternalError (chains cause)",
			factory: () =>
				new InternalError("DB_FAIL", "query failed", internalCause),
			expectedName: "InternalError",
			kind: "E_INTERNAL",
			code: "DB_FAIL",
			qualifiedCode: "E_INTERNAL_DB_FAIL",
			cause: internalCause,
		},
		{
			name: "InvariantError",
			factory: () => new InvariantError("BROKEN", "msg"),
			expectedName: "InvariantError",
			kind: "E_INVARIANT",
			code: "BROKEN",
			qualifiedCode: "E_INVARIANT_BROKEN",
		},
		{
			name: "ValidationError",
			factory: () =>
				new ValidationError("SHAPE", [{ path: "x", message: "bad" }]),
			expectedName: "ValidationError",
			kind: "E_VALIDATION",
			code: "SHAPE",
			qualifiedCode: "E_VALIDATION_SHAPE",
		},
		{
			name: "UserValidationError",
			factory: () =>
				new UserValidationError("INPUT", [{ path: "x", message: "y" }]),
			expectedName: "UserValidationError",
			kind: "E_USER",
			code: "INPUT",
			qualifiedCode: "E_USER_INPUT",
			extraInstances: [UserError],
		},
		{
			name: "UserValidationError (chains cause)",
			factory: () =>
				new UserValidationError(
					"INPUT",
					[{ path: "x", message: "y" }],
					undefined,
					undefined,
					userValidationCause,
				),
			expectedName: "UserValidationError",
			kind: "E_USER",
			code: "INPUT",
			qualifiedCode: "E_USER_INPUT",
			cause: userValidationCause,
			extraInstances: [UserError],
		},
	];

	it.each(cases)(
		"$name",
		({
			factory,
			expectedName,
			kind,
			code,
			qualifiedCode,
			cause,
			extraInstances,
		}) => {
			const err = factory();

			expect(err.name).toBe(expectedName);
			expect(err.kind).toBe(kind);
			expect(err.code).toBe(code);
			expect(err.qualifiedCode).toBe(qualifiedCode);
			expect(err.cause).toBe(cause);
			expect(err).toBeInstanceOf(Error);
			expect(err).toBeInstanceOf(CodedError);

			for (const ctor of extraInstances ?? []) {
				expect(err).toBeInstanceOf(ctor);
			}
		},
	);
});

// ---------------------------------------------------------------------------
// toJSON
// ---------------------------------------------------------------------------

describe("toJSON", () => {
	const jsonCause = new Error("root");

	interface JsonCase {
		name: string;
		factory: () => CodedError;
		expected: Record<string, unknown>;
		exact: boolean;
		roundTrip: boolean;
	}

	const cases: JsonCase[] = [
		{
			name: "serializes base fields exactly",
			factory: () => new UserError("INVALID_NAME", "Name is required"),
			expected: {
				name: "UserError",
				kind: "E_USER",
				code: "INVALID_NAME",
				qualifiedCode: "E_USER_INVALID_NAME",
				message: "Name is required",
				cause: undefined,
			},
			exact: true,
			roundTrip: false,
		},
		{
			name: "round-trips base fields through JSON.stringify",
			factory: () => new UserError("X", "msg"),
			expected: { name: "UserError", kind: "E_USER", code: "X" },
			exact: false,
			roundTrip: true,
		},
		{
			name: "includes cause when present",
			factory: () => new InternalError("FAIL", "msg", jsonCause),
			expected: { kind: "E_INTERNAL", cause: jsonCause },
			exact: false,
			roundTrip: false,
		},
		{
			name: "ApiError includes status",
			factory: () => new ApiError("NOT_FOUND", 404, "Not found"),
			expected: { kind: "E_API", status: 404 },
			exact: false,
			roundTrip: true,
		},
		{
			name: "ValidationError includes issues",
			factory: () =>
				new ValidationError("SHAPE_MISMATCH", [
					{ path: "name", message: "Missing required field: name" },
				]),
			expected: {
				kind: "E_VALIDATION",
				code: "SHAPE_MISMATCH",
				issues: [
					{ path: "name", message: "Missing required field: name" },
				],
			},
			exact: false,
			roundTrip: true,
		},
		{
			name: "UserValidationError serializes redacted issues",
			factory: () =>
				new UserValidationError(
					"INPUT",
					[{ path: "pw", message: "got secret123" }],
					["secret123"],
				),
			expected: {
				kind: "E_USER",
				code: "INPUT",
				message: "Validation failed (1 issue)",
				issues: [{ path: "pw", message: "got ****" }],
			},
			exact: false,
			roundTrip: false,
		},
		{
			name: "UserValidationError round-trips with redaction intact",
			factory: () =>
				new UserValidationError(
					"AUTH",
					[{ path: "token", message: "bad value abc123" }],
					["abc123"],
				),
			expected: {
				kind: "E_USER",
				code: "AUTH",
				issues: [{ path: "token", message: "bad value ****" }],
			},
			exact: false,
			roundTrip: true,
		},
	];

	it.each(cases)("$name", ({ factory, expected, exact, roundTrip }) => {
		const err = factory();
		const json = err.toJSON();

		if (exact) {
			expect(json).toEqual(expected);
		} else {
			expect(json).toEqual(expect.objectContaining(expected));
		}

		if (roundTrip) {
			const parsed: unknown = JSON.parse(JSON.stringify(err));
			expect(parsed).toEqual(expect.objectContaining(expected));
		}
	});
});

// ---------------------------------------------------------------------------
// isInstance - duck-type guards
// ---------------------------------------------------------------------------

describe("isInstance", () => {
	interface ErrorCase {
		name: string;
		err: unknown;
		user: boolean;
		api: boolean;
		internal: boolean;
		invariant: boolean;
		validation: boolean;
		userValidation: boolean;
	}

	const cases: ErrorCase[] = [
		{
			name: "UserError",
			err: new UserError("X", "msg"),
			user: true,
			api: false,
			internal: false,
			invariant: false,
			validation: false,
			userValidation: false,
		},
		{
			name: "ApiError",
			err: new ApiError("Y", 500, "msg"),
			user: false,
			api: true,
			internal: false,
			invariant: false,
			validation: false,
			userValidation: false,
		},
		{
			name: "InternalError",
			err: new InternalError("Z", "msg"),
			user: false,
			api: false,
			internal: true,
			invariant: false,
			validation: false,
			userValidation: false,
		},
		{
			name: "InvariantError",
			err: new InvariantError("W", "msg"),
			user: false,
			api: false,
			internal: false,
			invariant: true,
			validation: false,
			userValidation: false,
		},
		{
			name: "ValidationError",
			err: new ValidationError("SHAPE", [{ path: "x", message: "bad" }]),
			user: false,
			api: false,
			internal: false,
			invariant: false,
			validation: true,
			userValidation: false,
		},
		{
			name: "UserValidationError",
			err: new UserValidationError("INPUT", [
				{ path: "x", message: "bad" },
			]),
			user: true,
			api: false,
			internal: false,
			invariant: false,
			validation: false,
			userValidation: true,
		},
		{
			name: "plain Error",
			err: new Error("plain"),
			user: false,
			api: false,
			internal: false,
			invariant: false,
			validation: false,
			userValidation: false,
		},
		{
			name: "string",
			err: "not an error",
			user: false,
			api: false,
			internal: false,
			invariant: false,
			validation: false,
			userValidation: false,
		},
		{
			name: "null",
			err: null,
			user: false,
			api: false,
			internal: false,
			invariant: false,
			validation: false,
			userValidation: false,
		},
		{
			name: "duck-typed UserError-like object",
			err: { kind: "E_USER", code: "DUCK", message: "quack" },
			user: true,
			api: false,
			internal: false,
			invariant: false,
			validation: false,
			userValidation: false,
		},
		{
			name: "duck-typed ApiError-like object (missing status)",
			err: { kind: "E_API", code: "DUCK", message: "quack" },
			user: false,
			api: false,
			internal: false,
			invariant: false,
			validation: false,
			userValidation: false,
		},
		{
			name: "duck-typed ApiError-like object (with status)",
			err: { kind: "E_API", code: "DUCK", message: "quack", status: 503 },
			user: false,
			api: true,
			internal: false,
			invariant: false,
			validation: false,
			userValidation: false,
		},
		{
			name: "duck-typed ValidationError-like object",
			err: {
				kind: "E_VALIDATION",
				code: "X",
				message: "m",
				issues: [{ path: "a", message: "b" }],
			},
			user: false,
			api: false,
			internal: false,
			invariant: false,
			validation: true,
			userValidation: false,
		},
		{
			name: "duck-typed UserValidation-like object",
			err: {
				kind: "E_USER",
				code: "X",
				message: "m",
				issues: [{ path: "a", message: "b" }],
			},
			user: true,
			api: false,
			internal: false,
			invariant: false,
			validation: false,
			userValidation: true,
		},
	];

	it.each(cases)(
		"$name: user=$user, api=$api, internal=$internal, invariant=$invariant, validation=$validation, userValidation=$userValidation",
		({
			err,
			user,
			api,
			internal,
			invariant,
			validation,
			userValidation,
		}) => {
			expect(UserError.isInstance(err)).toBe(user);
			expect(ApiError.isInstance(err)).toBe(api);
			expect(InternalError.isInstance(err)).toBe(internal);
			expect(InvariantError.isInstance(err)).toBe(invariant);
			expect(ValidationError.isInstance(err)).toBe(validation);
			expect(UserValidationError.isInstance(err)).toBe(userValidation);
		},
	);
});

// ---------------------------------------------------------------------------
// Consumer extensibility
// ---------------------------------------------------------------------------

describe("consumer extensibility", () => {
	const ENTRY_CODES = ["INVALID_NAME", "INVALID_EMAIL"] as const;

	class InvalidEntryError extends UserError {
		constructor(
			code: (typeof ENTRY_CODES)[number],
			message: string,
			cause?: unknown,
		) {
			super(code, message, cause);
		}

		static override isInstance(err: unknown): err is InvalidEntryError {
			if (!UserError.isInstance(err)) {
				return false;
			}
			for (const code of ENTRY_CODES) {
				if (err.code === code) {
					return true;
				}
			}
			return false;
		}
	}

	interface GuardCase {
		name: string;
		guard: (err: unknown) => boolean;
		err: unknown;
		expected: boolean;
	}

	const guardCases: GuardCase[] = [
		{
			name: "subclass recognized by parent isInstance",
			guard: (err) => UserError.isInstance(err),
			err: new InvalidEntryError("INVALID_NAME", "bad name"),
			expected: true,
		},
		{
			name: "subclass isInstance rejects non-matching codes",
			guard: (err) => InvalidEntryError.isInstance(err),
			err: new UserError("OTHER_CODE", "msg"),
			expected: false,
		},
		{
			name: "subclass isInstance accepts matching codes",
			guard: (err) => InvalidEntryError.isInstance(err),
			err: new InvalidEntryError("INVALID_EMAIL", "bad email"),
			expected: true,
		},
		{
			name: "cross-class rejection via InternalError",
			guard: (err) => InternalError.isInstance(err),
			err: new InvalidEntryError("INVALID_NAME", "bad"),
			expected: false,
		},
		{
			name: "cross-class rejection via ApiError",
			guard: (err) => ApiError.isInstance(err),
			err: new InvalidEntryError("INVALID_NAME", "bad"),
			expected: false,
		},
	];

	it.each(guardCases)("$name → $expected", ({ guard, err, expected }) => {
		expect(guard(err)).toBe(expected);
	});

	it("subclass qualifiedCode includes parent kind", () => {
		const err = new InvalidEntryError("INVALID_NAME", "bad");
		expect(err.qualifiedCode).toBe("E_USER_INVALID_NAME");
	});
});

// ---------------------------------------------------------------------------
// errorMessage
// ---------------------------------------------------------------------------

describe("errorMessage", () => {
	it.each([
		{ name: "Error instance", input: new Error("boom"), expected: "boom" },
		{ name: "TypeError", input: new TypeError("type"), expected: "type" },
		{ name: "string", input: "raw string", expected: "raw string" },
		{ name: "number", input: 42, expected: "42" },
		{ name: "null", input: null, expected: "null" },
		{ name: "undefined", input: undefined, expected: "undefined" },
		{ name: "object", input: { toString: () => "obj" }, expected: "obj" },
	])("extracts message from $name", ({ input, expected }) => {
		expect(errorMessage(input)).toBe(expected);
	});
});

// ---------------------------------------------------------------------------
// ValidationError
// ---------------------------------------------------------------------------

describe("ValidationError", () => {
	const twoIssues: readonly ValidationIssue[] = [
		{ path: "name", message: "Missing required field: name" },
		{ path: "age", message: "Field age must be number, got string" },
	];

	interface ConstructionCase {
		name: string;
		code: string;
		issues: readonly ValidationIssue[];
		message?: string;
		cause?: Error;
		expectedMessage: string;
	}

	const cases: ConstructionCase[] = [
		{
			name: "default plural message",
			code: "SHAPE_MISMATCH",
			issues: twoIssues,
			expectedMessage: "Validation failed (2 issues)",
		},
		{
			name: "default singular message",
			code: "SHAPE_MISMATCH",
			issues: [twoIssues[0]!],
			expectedMessage: "Validation failed (1 issue)",
		},
		{
			name: "custom message",
			code: "SHAPE_MISMATCH",
			issues: twoIssues,
			message: "bad payload",
			expectedMessage: "bad payload",
		},
		{
			name: "with cause",
			code: "X",
			issues: twoIssues,
			cause: new Error("root"),
			expectedMessage: "Validation failed (2 issues)",
		},
	];

	it.each(cases)(
		"$name",
		({ code, issues, message, cause, expectedMessage }) => {
			const err = new ValidationError(code, issues, message, cause);

			expect(err.message).toBe(expectedMessage);
			expect(err.issues).toEqual(issues);
			expect(err.cause).toBe(cause);
		},
	);
});

// ---------------------------------------------------------------------------
// UserValidationError
// ---------------------------------------------------------------------------

describe("UserValidationError", () => {
	const baseIssues: readonly ValidationIssue[] = [
		{ path: "email", message: "Field email must be string, got number" },
		{
			path: "password",
			message: "Field password must be one of [strong, weak], got s3cr3t",
		},
	];

	describe("construction and redaction", () => {
		interface ConstructionCase {
			name: string;
			issues: readonly ValidationIssue[];
			sensitive?: readonly string[];
			message?: string;
			expectedMessage: string;
			expectedIssueMessages: string[];
		}

		const cases: ConstructionCase[] = [
			{
				name: "single issue - singular default message",
				issues: [baseIssues[0]!],
				expectedMessage: "Validation failed (1 issue)",
				expectedIssueMessages: [
					"Field email must be string, got number",
				],
			},
			{
				name: "multiple issues - plural default message",
				issues: baseIssues,
				expectedMessage: "Validation failed (2 issues)",
				expectedIssueMessages: [
					"Field email must be string, got number",
					"Field password must be one of [strong, weak], got s3cr3t",
				],
			},
			{
				name: "custom message without sensitive values",
				issues: baseIssues,
				message: "Invalid user input",
				expectedMessage: "Invalid user input",
				expectedIssueMessages: [
					"Field email must be string, got number",
					"Field password must be one of [strong, weak], got s3cr3t",
				],
			},
			{
				name: "redacts sensitive value from issue messages",
				issues: baseIssues,
				sensitive: ["s3cr3t"],
				expectedMessage: "Validation failed (2 issues)",
				expectedIssueMessages: [
					"Field email must be string, got number",
					"Field password must be one of [strong, weak], got ****",
				],
			},
			{
				name: "redacts sensitive value from custom message",
				issues: baseIssues,
				sensitive: ["s3cr3t"],
				message: "Failed for s3cr3t",
				expectedMessage: "Failed for ****",
				expectedIssueMessages: [
					"Field email must be string, got number",
					"Field password must be one of [strong, weak], got ****",
				],
			},
			{
				name: "redacts multiple sensitive values",
				issues: [
					{ path: "auth", message: "got token123 and secret456" },
				],
				sensitive: ["token123", "secret456"],
				expectedMessage: "Validation failed (1 issue)",
				expectedIssueMessages: ["got **** and ****"],
			},
			{
				name: "redacts repeated occurrences in one message",
				issues: [{ path: "x", message: "abc abc abc" }],
				sensitive: ["abc"],
				expectedMessage: "Validation failed (1 issue)",
				expectedIssueMessages: ["**** **** ****"],
			},
			{
				name: "empty sensitive array does not redact",
				issues: baseIssues,
				sensitive: [],
				expectedMessage: "Validation failed (2 issues)",
				expectedIssueMessages: [
					"Field email must be string, got number",
					"Field password must be one of [strong, weak], got s3cr3t",
				],
			},
		];

		it.each(cases)(
			"$name",
			({
				issues,
				sensitive,
				message,
				expectedMessage,
				expectedIssueMessages,
			}) => {
				const err = new UserValidationError(
					"INPUT",
					issues,
					sensitive,
					message,
				);
				expect(err.message).toBe(expectedMessage);
				const messages = err.issues.map((i) => i.message);
				expect(messages).toEqual(expectedIssueMessages);
			},
		);
	});

	describe("isInstance", () => {
		interface GuardCase {
			name: string;
			err: unknown;
			expected: boolean;
		}

		const cases: GuardCase[] = [
			{
				name: "UserValidationError instance",
				err: new UserValidationError("INPUT", [
					{ path: "x", message: "y" },
				]),
				expected: true,
			},
			{
				name: "plain UserError (no issues)",
				err: new UserError("X", "msg"),
				expected: false,
			},
			{
				name: "ValidationError (different kind)",
				err: new ValidationError("X", [{ path: "x", message: "y" }]),
				expected: false,
			},
			{
				name: "duck-typed with issues",
				err: {
					kind: "E_USER",
					code: "DUCK",
					message: "msg",
					issues: [{ path: "x", message: "y" }],
				},
				expected: true,
			},
			{
				name: "duck-typed without issues",
				err: { kind: "E_USER", code: "DUCK", message: "msg" },
				expected: false,
			},
			{
				name: "null",
				err: null,
				expected: false,
			},
		];

		it.each(cases)("$name → $expected", ({ err, expected }) => {
			expect(UserValidationError.isInstance(err)).toBe(expected);
		});

		it("passes parent UserError.isInstance", () => {
			const err = new UserValidationError("INPUT", [
				{ path: "x", message: "y" },
			]);
			expect(UserError.isInstance(err)).toBe(true);
		});
	});
});
