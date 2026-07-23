import type { CompressedRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";
import { PROFILE_OIDS } from "@wahidgroup/tightbeam-ws-client";

import { muxClearEndpoint } from "../env.js";
import { openApp } from "./helpers.js";

test("compresses a body with the profile zstd, echoes it, and inflates it", async ({
	page,
}) => {
	await openApp(page);

	const result: CompressedRoundTripResult = await page.evaluate(
		({ url }) =>
			window.tbCompressedRoundTrip(url, "cafebabe0042", "e2e-packed", 15),
		{ url: muxClearEndpoint },
	);
	expect(result.compressed).toBe(true);
	expect(result.compactnessOid).toBe(PROFILE_OIDS.zstd);
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
		{ url: muxClearEndpoint },
	);
	expect(result.compressed).toBe(true);
	expect(result.compactnessOid).toBe(PROFILE_OIDS.zstd);
	expect(result.inflatedHex).toBe("cafebabe0042");
});
