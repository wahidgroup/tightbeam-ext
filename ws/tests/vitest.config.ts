import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		conditions: ["node", "import", "default"],
	},
	test: {
		environment: "node",
		include: ["node/**/*.test.ts"],
		root: ".",
		setupFiles: ["../../scripts/vitest/byte-equality.mjs"],
		pool: "forks",
		// A case of the lane collects garbage to show that a body keeps no chunk
		// it yielded.
		execArgv: ["--expose-gc"],
	},
});
