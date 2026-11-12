import { describe, expect, expectTypeOf, it } from "vitest";

import type { RefusalCode, TransitCode, TransportCode } from "#wasm";

import type { ClientCode, TransportError } from "./errors.js";
import { ClientTransportError, StreamRefusal } from "./errors.js";
import { Engine } from "./index.js";

const engine = await Engine.load();

/**
 * A rejection shaped like the wasm layer's structured transport errors.
 */
function structuredError(code: string): Error {
	const error = new Error("connection draining after GoAway");
	error.name = "TightbeamTransportError";
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
	error.name = "TightbeamTransportError";
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

	it.each(["WorkRefused", "OpaqueBody"])("does not narrow a forged %s that carries no detail", (code) => {
		const forged = structuredError(code);
		expect(engine.isTransportError(forged)).toBe(false);
	});

	it("does not narrow a forged refusal named Ok, which names no refusal", () => {
		const forged = structuredError("Ok");
		expect(engine.isTransportError(forged)).toBe(false);
	});

	it("narrows the opaque body the client decided, with the layer it lacks", () => {
		const opaque = ClientTransportError.opaqueBody("opener");
		expect(engine.isTransportError(opaque)).toBe(true);
		expect(opaque).toMatchObject({ code: "OpaqueBody", layer: "opener" });
	});

	it.each(FOREIGN_REJECTIONS)("rejects $label", ({ value }) => {
		expect(engine.isTransportError(value)).toBe(false);
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

	it("settles a served stream with the code of a StreamRefusal", () => {
		const refusal = new StreamRefusal("PermissionDenied", "not yours");
		expect(StreamRefusal.settlement(refusal)).toBe("PermissionDenied");
	});

	it.each([
		{ label: "a rethrown engine error", thrown: thrownBy(() => engine.oid("not-an-oid")) },
		{ label: "an error the client decided", thrown: ClientTransportError.closed("emit") },
		{ label: "a bare status name", thrown: "NotFound" },
		{ label: "an object that names a status", thrown: { code: "Unavailable" } },
		{ label: "undefined", thrown: undefined },
	])("settles a served stream with Unknown for $label", ({ thrown }) => {
		expect(StreamRefusal.settlement(thrown)).toBe("Unknown");
	});
});

describe("TransportError", () => {
	it("each code family declares codes no other family declares", () => {
		type EngineCodes = RefusalCode | TransportCode;

		expectTypeOf<Extract<RefusalCode, TransportCode>>().toBeNever();
		expectTypeOf<Extract<EngineCodes, TransitCode>>().toBeNever();
		expectTypeOf<Extract<EngineCodes | TransitCode, ClientCode>>().toBeNever();
	});

	it("a check of the code narrows to the member that carries its detail", () => {
		type WorkRefused = Extract<TransportError, { readonly code: "WorkRefused" }>;
		type OpaqueBody = Extract<TransportError, { readonly code: "OpaqueBody" }>;
		type Draining = TransportError & { readonly code: "Draining" };

		expectTypeOf<WorkRefused["status"]>().toEqualTypeOf<TransitCode>();
		expectTypeOf<OpaqueBody["layer"]>().toEqualTypeOf<"opener" | "inflator">();
		expectTypeOf<"status" extends keyof Draining ? true : false>().toEqualTypeOf<false>();
	});
});
