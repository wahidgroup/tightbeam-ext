import { defineConfig } from "eslint/config";
import base from "@wahidgroup/lint-rules/eslint/base";
import playwright from "@wahidgroup/lint-rules/eslint/playwright";

import { realDependencies } from "../../scripts/eslint/real-dependencies.mjs";

export default defineConfig(
	...base,
	realDependencies,
	...playwright.map((config) => ({
		...config,
		// The node/ lane is vitest, not Playwright.
		files: ["app/**", "specs/**", "*.ts"],
	})),
	{
		ignores: ["test-results/", "playwright-report/"],
	},
);
