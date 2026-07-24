import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		environment: "node",
		include: ["node/**/*.test.ts"],
		exclude: ["node_modules"],
		root: ".",
	},
	resolve: {
		alias: {
			/*
			 * The node-lane harness is shared with the ws extension at the
			 * source level: one file, no copies (see the e2e README section).
			 */
			"#ws-harness": resolve(
				import.meta.dirname,
				"../../ws/tests/node/harness.ts",
			),
		},
	},
});
