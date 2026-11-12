import { defineConfig, devices } from "@playwright/test";

import { APP_PORT } from "./app_port.js";

const baseURL = `http://localhost:${APP_PORT}`;

/**
 * The dockerized pubsub demo server is owned by scripts/stack.sh, and
 * scripts/test-e2e.sh exports its endpoint as PUBSUB_WS_ENDPOINT, which the
 * `STACK` of node/stack.ts reads.
 */
export default defineConfig({
	testDir: "./specs",
	fullyParallel: false,
	forbidOnly: Boolean(process.env.CI),
	retries: 0,
	reporter: "list",
	use: {
		baseURL,
		trace: "retain-on-failure",
	},
	webServer: {
		command: "npm run dev",
		url: baseURL,
		reuseExistingServer: !process.env.CI,
		timeout: 120_000,
	},
	projects: [
		{
			name: "chromium",
			use: { ...devices["Desktop Chrome"] },
		},
	],
});
