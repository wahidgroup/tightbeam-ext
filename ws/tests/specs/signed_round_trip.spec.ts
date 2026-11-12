import type { SignedRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { STACK } from "../stack.js";
import { openApp } from "./helpers.js";

test("signs a frame, echoes it, and verifies the round-tripped signature", async ({ page }) => {
	await openApp(page);

	const result: SignedRoundTripResult = await page.evaluate((echo) => window.tb.signedRoundTrip(echo), {
		url: STACK.muxClearEndpoint,
		payloadHex: "cafebabe0042",
		idText: "e2e-signed",
		order: 13,
		signingKeyHex: "01".repeat(32),
		saltHex: "5a".repeat(16),
	});
	expect(result.bodyHex).toBe("cafebabe0042");
	expect(result.idText).toBe("e2e-signed");
	expect(result.order).toBe("13");
	expect(result.signed).toBe(true);
	expect(result.messageIntegrity).toBe(true);
	expect(result.frameIntegrity).toBe(true);
	expect(result.signatureValid).toBe(true);
	expect(result.frameVerdict).toBe("verified");
	expect(result.messageVerdict).toBe("verified");
	expect(result.wrongSaltVerdict).toBe("mismatch");
});
