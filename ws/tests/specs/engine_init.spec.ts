import type { CustomInputResult } from "../app/engine.js";
import { expect, test } from "@playwright/test";

/**
 * A binary the host of the e2e app does not serve.
 */
const UNSERVED_BINARY = "/unserved/tightbeam_ws_wasm_bg.wasm";

/**
 * What the page answers once the engine loaded and built a frame of
 * `cafe0042`.
 */
const LOADED: CustomInputResult = {
	oid: "1.2.840.113549.1.7.1",
	bodyHex: "cafe0042",
};

test("init with a custom module input loads the engine", async ({ page }) => {
	await page.goto("/engine.html");
	await expect(page.locator("#status")).toHaveText("page ready");

	// The page compiled its input already, so a load that fetches a binary
	// dropped the input.
	await page.route("**/*.wasm", (route) => route.abort());

	const result: CustomInputResult = await page.evaluate(() =>
		window.tbInitWithInput("cafe0042"),
	);
	expect(result).toEqual(LOADED);
});

test("a failed load rejects init with EngineUnavailable, and a later init loads", async ({
	page,
}) => {
	await page.goto("/engine.html");
	await expect(page.locator("#status")).toHaveText("page ready");

	const refusal = await page.evaluate(
		(source) => window.tbInitRefusal(source),
		UNSERVED_BINARY,
	);
	const result: CustomInputResult = await page.evaluate(() =>
		window.tbInitWithInput("cafe0042"),
	);
	expect(refusal).toBe("EngineUnavailable");
	expect(result).toEqual(LOADED);
});
