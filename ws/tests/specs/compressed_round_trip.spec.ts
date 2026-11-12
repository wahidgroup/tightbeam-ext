import type { CompressedRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { Engine } from "@wahidgroup/tightbeam-ws-client";

import { STACK } from "../stack.js";
import { openApp } from "./helpers.js";

const ENGINE = await Engine.load();

/**
 * The dotted object identifier of zstd, the profile compression, as the engine reads it.
 */
const ZSTD_OID = ENGINE.profile.zstd.toString();

test("compresses a body with the profile zstd, echoes it, and inflates it", async ({ page }) => {
	await openApp(page);

	const result: CompressedRoundTripResult = await page.evaluate((echo) => window.tb.compressedRoundTrip(echo), {
		url: STACK.muxClearEndpoint,
		payloadHex: "cafebabe0042",
		idText: "e2e-packed",
		order: 15,
	});
	expect(result.compressed).toBe(true);
	expect(result.compactnessOid).toBe(ZSTD_OID);
	expect(result.inflatedHex).toBe("cafebabe0042");
});

test("compresses then seals a body, echoes it, and recovers it with key and inflator", async ({ page }) => {
	await openApp(page);

	const result: CompressedRoundTripResult = await page.evaluate((echo) => window.tb.compressedSealedRoundTrip(echo), {
		url: STACK.muxClearEndpoint,
		payloadHex: "cafebabe0042",
		idText: "e2e-packed-sealed",
		order: 16,
	});
	expect(result.compressed).toBe(true);
	expect(result.compactnessOid).toBe(ZSTD_OID);
	expect(result.inflatedHex).toBe("cafebabe0042");
});
