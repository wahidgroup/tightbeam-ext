import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		environment: "node",
		include: ["**/*.test.ts"],
		exclude: ["node_modules", "fixture"],
		setupFiles: ["../../scripts/vitest/byte-equality.mjs"],
	},
});
