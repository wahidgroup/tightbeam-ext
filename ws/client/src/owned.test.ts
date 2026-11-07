import { describe, expect, it } from "vitest";

import { ClientTransportError } from "./errors.js";
import { TightbeamWsClient } from "./index.js";
import { Owned } from "./owned.js";

/**
 * The hold of a real glue handle. Every kind-3 holder releases through
 * {@link Owned}, so this one test proves the release for each of them.
 */

const engine = await TightbeamWsClient.init();

/**
 * The content type `id-data`, whose glue handle the test holds.
 */
const DATA = "1.2.840.113549.1.7.1";

describe("Owned", () => {
	it("a release frees the held handle once, and a later use refuses with KeyReleased", () => {
		const handle = engine.oid(DATA);
		const hold = new Owned(handle, ClientTransportError.keyReleased);
		hold[Symbol.dispose]();
		expect(() => handle.toString()).toThrow();
		expect(() => hold[Symbol.dispose]()).not.toThrow();
		expect(() => hold.use("toString")).toThrow(
			expect.objectContaining({ code: "KeyReleased" }),
		);
	});
});
