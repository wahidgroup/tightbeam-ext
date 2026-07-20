/**
 * Shared Playwright helpers for the e2e specs.
 */

import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

/**
 * Navigate to the example app and wait until the wasm client is ready.
 */
export async function openApp(page: Page): Promise<void> {
	await page.goto("/");
	await expect(page.locator("#status")).toHaveText("client ready");
}
