import type { SealedRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { Engine } from "@wahidgroup/tightbeam-ws-client";

import { STACK } from "../stack.js";
import { openApp } from "./helpers.js";

const ENGINE = await Engine.load();

test("seals a body with AES-256-GCM, echoes it, and opens it with the key", async ({ page }) => {
	await openApp(page);

	const result: SealedRoundTripResult = await page.evaluate((echo) => window.tb.sealedRoundTrip(echo), {
		url: STACK.muxClearEndpoint,
		payloadHex: "cafebabe0042",
		idText: "e2e-sealed",
		order: 14,
	});
	expect(result.confidential).toBe(true);
	expect(result.confidentialityOid).toBe(ENGINE.profile.aes256Gcm.toString());
	expect(result.ciphertextDiffers).toBe(true);
	expect(result.decryptedHex).toBe("cafebabe0042");
});
