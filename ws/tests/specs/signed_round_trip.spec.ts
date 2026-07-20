import type { SignedRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { wsEndpoint } from "../env.js";
import { openApp } from "./helpers.js";

test("signs a frame, echoes it, and verifies the round-tripped signature", async ({
	page,
}) => {
	await openApp(page);

	const result: SignedRoundTripResult = await page.evaluate(
		({ url }) =>
			window.tbSignedRoundTrip(
				url,
				"cafebabe0042",
				"e2e-signed",
				13,
				"0101010101010101010101010101010101010101010101010101010101010101",
				"5a5a5a5a",
			),
		{ url: wsEndpoint },
	);
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
