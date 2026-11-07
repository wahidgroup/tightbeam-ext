import { describe, expect, expectTypeOf, it } from "vitest";

import type { RefusalCode, TransitCode, TransportCode } from "#wasm";

import type { ClientCode, TransportErrorCode } from "./errors.js";
import { ClientTransportError, StreamRefusal } from "./errors.js";
import { TightbeamWsClient } from "./index.js";

const engine = await TightbeamWsClient.init();

/**
 * A rejection shaped like the wasm layer's structured transport errors.
 */
function structuredError(code: string): Error {
	const error = new Error("connection draining after GoAway");
	error.name = ClientTransportError.NAME;
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
	error.name = ClientTransportError.NAME;
	return error;
}

/**
 * What `refused` throws.
 */
function thrownBy(refused: () => unknown): unknown {
	try {
		refused();
	} catch (error) {
		return error;
	}

	return undefined;
}

describe("Engine.isTransportError", () => {
	it("narrows an error that the engine raised", () => {
		const raised = thrownBy(() => engine.oid("not-an-oid"));
		expect(engine.isTransportError(raised)).toBe(true);
	});

	it("narrows an error that the client decided", () => {
		const decided = ClientTransportError.keyReleased("sign");
		expect(engine.isTransportError(decided)).toBe(true);
	});

	it("does not narrow a forged error with the name brand and an unknown code", () => {
		const forged = structuredError("NoSuchCode");
		expect(engine.isTransportError(forged)).toBe(false);
	});

	it.each(FOREIGN_REJECTIONS)("rejects $label", ({ value }) => {
		expect(engine.isTransportError(value)).toBe(false);
	});
});

describe("ClientTransportError.isConnectionClosed", () => {
	it("recognizes a structured ConnectionClosed rejection", () => {
		const rejection = structuredError("ConnectionClosed");
		expect(ClientTransportError.isConnectionClosed(rejection)).toBe(true);
	});

	it("recognizes the refusal of an operation on a released client", () => {
		const refusal = ClientTransportError.closed("emit");
		expect(ClientTransportError.isConnectionClosed(refusal)).toBe(true);
	});

	it.each(["Draining", "StreamsExhausted"])(
		"refuses a structured rejection whose code is %s",
		(code) => {
			const rejection = structuredError(code);
			expect(ClientTransportError.isConnectionClosed(rejection)).toBe(
				false,
			);
		},
	);

	it("refuses a plain Error that only carries the code", () => {
		const imitation = Object.assign(new Error("closed"), {
			code: "ConnectionClosed",
		});
		expect(ClientTransportError.isConnectionClosed(imitation)).toBe(false);
	});

	it.each(FOREIGN_REJECTIONS)("refuses $label", ({ value }) => {
		expect(ClientTransportError.isConnectionClosed(value)).toBe(false);
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

describe("TransportErrorCode", () => {
	it("each code family declares codes no other family declares", () => {
		type EngineCodes = RefusalCode | TransportCode;

		expectTypeOf<Extract<RefusalCode, TransportCode>>().toBeNever();
		expectTypeOf<Extract<EngineCodes, TransitCode>>().toBeNever();
		expectTypeOf<
			Extract<EngineCodes | TransitCode, ClientCode>
		>().toBeNever();
	});

	it("a transport error carries a closed code, and only the class builds one", () => {
		const build = (): unknown =>
			// @ts-expect-error The constructor is private: a named static builds each code.
			new ClientTransportError("ConnectionClosed", "closed");
		expectTypeOf(build).toBeFunction();
		expectTypeOf<
			ClientTransportError["code"]
		>().toEqualTypeOf<TransportErrorCode>();
		expectTypeOf<string>().not.toExtend<TransportErrorCode>();
	});
});
