import { defineConfig } from "eslint/config";
import base from "@wahidgroup/lint-rules/eslint/base";
import playwright from "@wahidgroup/lint-rules/eslint/playwright";

export default defineConfig(...base, ...playwright, {
	ignores: ["test-results/", "playwright-report/"],
});
