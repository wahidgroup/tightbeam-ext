/**
 * Shared Playwright helpers for the e2e specs.
 */

import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

import { STACK } from "../stack.js";

/**
 * Open the example app with the dial facts of the stack in its query
 * string, and wait until the wasm client is ready.
 */
export async function openApp(page: Page): Promise<void> {
	const query = new URLSearchParams(STACK.dial.params());
	await page.goto(`/?${query.toString()}`);
	await expect(page.locator("#status")).toHaveText("client ready");
}
