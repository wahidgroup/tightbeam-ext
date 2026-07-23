import type { TypedRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { muxClearEndpoint } from "../env.js";
import { openApp } from "./helpers.js";

test("round-trips a typed message under a wrapped payload codec", async ({
	page,
}) => {
	await openApp(page);

	const result: TypedRoundTripResult = await page.evaluate(
		({ url }) =>
			window.tbTypedRoundTrip(url, "e2e-typed", 17, "ada", "hello"),
		{ url: muxClearEndpoint },
	);
	expect(result).toEqual({ author: "ada", text: "hello" });
});
