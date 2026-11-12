import { describe, expect, it } from "vitest";

import type { MessageCodec } from "./index.js";
import { Engine, HeldCodec } from "./index.js";

/**
 * A codec held past the call that received it, on the real engine.
 */

const engine = await Engine.load();

/**
 * The content type `id-data`, which the held codec declares.
 */
const DATA = "1.2.840.113549.1.7.1";

/**
 * The profile opaque codec under the content type {@link DATA}.
 */
const DECLARING: MessageCodec<Uint8Array> = {
	contentOid: engine.oid(DATA),
	encode: (message) => engine.opaque.encode(message),
	decode: (bodyDer) => engine.opaque.decode(bodyDer),
};

/**
 * The refusal of a read of a released codec.
 */
const CODEC_RELEASED = expect.objectContaining({ code: "CodecReleased" });

describe("HeldCodec", () => {
	it("a disposed codec refuses a read of its content type with CodecReleased", () => {
		const held = HeldCodec.of(DECLARING);
		held[Symbol.dispose]();
		expect(() => held.contentOid).toThrow(CODEC_RELEASED);
	});

	it("a view the codec lent before its disposal refuses with CodecReleased after it", () => {
		const held = HeldCodec.of(DECLARING);
		const lent = held.contentOid;
		held[Symbol.dispose]();
		expect(() => lent?.toString()).toThrow(CODEC_RELEASED);
	});
});
