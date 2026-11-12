import { describe, expect, it } from "vitest";

import { Engine } from "./index.js";

/**
 * The load of the engine on the real node loader, whose first load in this
 * file is the concurrent pair, so that pair starts the realm.
 */

describe("Engine.load", () => {
	it("two concurrent loads resolve the same Engine", async () => {
		const first = Engine.load();
		const second = Engine.load();

		const engines = await Promise.all([first, second]);
		expect(engines[0]).toBe(engines[1]);
	});
});

describe("Engine dials", () => {
	it.each([
		{ name: "connect", args: [42, new Uint8Array(), undefined] },
		{ name: "connectCleartext", args: [42, undefined] },
	] as const)("$name refuses a url that is no string with a code at url", async ({ name, args }) => {
		const engine = await Engine.load();
		const dialing: unknown = Reflect.apply(engine[name], engine, args);
		await expect(dialing).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "InvalidText",
			path: "url",
		});
	});
});
