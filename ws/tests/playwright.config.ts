import { defineConfig, devices } from "@playwright/test";

let port = 4317; // default
if (process.env.E2E_APP_PORT) {
	port = Number(process.env.E2E_APP_PORT);
}

const baseURL = `http://localhost:${port}`;

/**
 * The dockerized echo servers are owned by scripts/stack.sh, and
 * scripts/test-e2e.sh exports their endpoints from the stack env file, under
 * the names that the `STACK` of stack.ts reads.
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
