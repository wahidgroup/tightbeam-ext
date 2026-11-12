import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitest/config";

// The unit tests run the sources, so the loader of the `node` condition
// resolves to its source, as the built package resolves it to `dist`.
const nodeLoader = fileURLToPath(new URL("src/engine/node.ts", import.meta.url));

export default defineConfig({
	resolve: {
		alias: {
			"#engine": nodeLoader,
		},
	},
	test: {
		environment: "node",
		include: ["src/**/*.test.ts"],
		exclude: ["node_modules", "dist"],
		root: ".",
		setupFiles: ["../../scripts/vitest/byte-equality.mjs"],
	},
});
