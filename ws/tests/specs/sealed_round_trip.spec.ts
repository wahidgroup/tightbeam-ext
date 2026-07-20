import type { SealedRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { wsEndpoint } from "../env.js";
import { openApp } from "./helpers.js";

test("seals a body with AES-256-GCM, echoes it, and opens it with the key", async ({
	page,
}) => {
	await openApp(page);

	const result: SealedRoundTripResult = await page.evaluate(
		({ url }) =>
			window.tbSealedRoundTrip(
				url,
				"cafebabe0042",
				"e2e-sealed",
				14,
				"0707070707070707070707070707070707070707070707070707070707070707",
			),
		{ url: wsEndpoint },
	);
	expect(result.confidential).toBe(true);
	expect(result.confidentialityOid).toBe("2.16.840.1.101.3.4.1.46");
	expect(result.ciphertextDiffers).toBe(true);
	expect(result.decryptedHex).toBe("cafebabe0042");
});
