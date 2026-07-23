import { describe, expect, it } from "vitest";

import {
	StreamRefusal,
	TRANSPORT_ERROR_NAME,
	isTransportError,
} from "./errors.js";

/**
 * A rejection shaped like the wasm layer's structured transport errors.
 */
function structuredError(code: string): Error {
	const error = new Error("connection draining after GoAway");
	error.name = TRANSPORT_ERROR_NAME;
	Object.assign(error, { code });
	return error;
}

/**
 * Rejections that MUST NOT narrow to a transport error.
 */
const FOREIGN_REJECTIONS = [
	{ label: "a plain Error", value: new Error("boom") },
	{ label: "a renamed Error without a code", value: structuredWithoutCode() },
	{ label: "a string", value: "Draining" },
	{ label: "undefined", value: undefined },
] as const;

function structuredWithoutCode(): Error {
	const error = new Error("no code property");
	error.name = TRANSPORT_ERROR_NAME;
	return error;
}

describe("isTransportError", () => {
	it("narrows a structured rejection and exposes its code", () => {
		const rejection: unknown = structuredError("Draining");

		expect(isTransportError(rejection)).toBe(true);
		expect(rejection).toMatchObject({ code: "Draining" });
	});

	it.each(FOREIGN_REJECTIONS)("rejects $label", ({ value }) => {
		expect(isTransportError(value)).toBe(false);
	});
});

describe("StreamRefusal", () => {
	it("carries the chosen status code and message", () => {
		const refusal = new StreamRefusal("NotFound", "no such order");

		expect(refusal).toBeInstanceOf(Error);
		expect(refusal).toMatchObject({
			name: "StreamRefusal",
			code: "NotFound",
			message: "no such order",
		});
	});
});
