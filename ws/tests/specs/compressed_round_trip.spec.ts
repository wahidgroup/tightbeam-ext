import type { CompressedRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { wsEndpoint } from "../env.js";
import { openApp } from "./helpers.js";

/**
 * The tightbeam profile zstd OID (`PROFILE_OIDS.zstd`).
 */
const ZSTD_OID = "1.3.6.1.4.1.55555.2.1";

test("compresses a body with the profile zstd, echoes it, and inflates it", async ({
	page,
}) => {
	await openApp(page);

	const result: CompressedRoundTripResult = await page.evaluate(
		({ url }) =>
			window.tbCompressedRoundTrip(url, "cafebabe0042", "e2e-packed", 15),
		{ url: wsEndpoint },
	);
	expect(result.compressed).toBe(true);
	expect(result.compactnessOid).toBe(ZSTD_OID);
	expect(result.inflatedHex).toBe("cafebabe0042");
});

test("compresses then seals a body, echoes it, and recovers it with key and inflator", async ({
	page,
}) => {
	await openApp(page);

	const result: CompressedRoundTripResult = await page.evaluate(
		({ url }) =>
			window.tbCompressedSealedRoundTrip(
				url,
				"cafebabe0042",
				"e2e-packed-sealed",
				16,
				"0707070707070707070707070707070707070707070707070707070707070707",
			),
		{ url: wsEndpoint },
	);
	expect(result.compressed).toBe(true);
	expect(result.compactnessOid).toBe(ZSTD_OID);
	expect(result.inflatedHex).toBe("cafebabe0042");
});
