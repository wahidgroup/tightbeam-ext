import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		conditions: ["node", "import", "default"],
	},
	test: {
		environment: "node",
		include: ["node/**/*.test.ts"],
		root: ".",
		pool: "forks",
	},
});
