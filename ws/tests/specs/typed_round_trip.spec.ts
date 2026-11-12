import type { TypedRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { STACK } from "../stack.js";
import { openApp } from "./helpers.js";

test("round-trips a typed message under a wrapped payload codec", async ({ page }) => {
	await openApp(page);

	const result: TypedRoundTripResult = await page.evaluate((echo) => window.tb.typedRoundTrip(echo), {
		url: STACK.muxClearEndpoint,
		idText: "e2e-typed",
		order: 17,
		note: { author: "ada", text: "hello" },
	});
	expect(result).toEqual({ author: "ada", text: "hello" });
});
