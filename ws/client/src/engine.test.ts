import { describe, expect, expectTypeOf, it } from "vitest";

import { Engine, Frame, FrameBuilder, TightbeamWsClient } from "./index.js";

/**
 * The load of the engine on the real node loader. No test in this file loads
 * the engine before the concurrent load, so that load starts the realm. The
 * browser e2e covers a failed load and its retry, because only the web loader
 * reads an input that can fail.
 */

/**
 * Octets that stand where a caller passes a frame or a message.
 */
const BYTES = new Uint8Array([1]);

/**
 * The one way to an {@link Engine}.
 */
type Init = typeof TightbeamWsClient.init;

describe("TightbeamWsClient.init", () => {
	it("two concurrent init() calls resolve the same Engine", async () => {
		const first = TightbeamWsClient.init();
		const second = TightbeamWsClient.init();

		const engines = await Promise.all([first, second]);
		expect(engines[0]).toBe(engines[1]);
	});

	it("a wasm call before init does not type-check", () => {
		const beforeInit = [
			// @ts-expect-error A builder needs the module that only an Engine holds.
			() => FrameBuilder.of(BYTES),
			// @ts-expect-error A frame needs the module that only an Engine holds.
			() => Frame.decode(BYTES),
			// @ts-expect-error Only TightbeamWsClient.init builds an Engine.
			() => new Engine(BYTES),
		];
		expectTypeOf(beforeInit).toBeArray();
		expectTypeOf(TightbeamWsClient).not.toHaveProperty("connect");
		expectTypeOf(TightbeamWsClient).not.toHaveProperty("connectMutual");
		expectTypeOf(TightbeamWsClient).not.toHaveProperty("connectCleartext");
		expectTypeOf(Frame).not.toHaveProperty("fromDer");
		expectTypeOf(Engine).not.toHaveProperty("over");
		expectTypeOf<Init>().returns.resolves.toEqualTypeOf<Engine>();
	});
});
