import { defineConfig } from "vitest/config";

import { SOURCE_ALIASES } from "./aliases.js";

export default defineConfig({
	test: {
		environment: "node",
		include: ["node/**/*.test.ts"],
		exclude: ["node_modules"],
		root: ".",
		setupFiles: ["../../scripts/vitest/byte-equality.mjs"],
	},
	resolve: {
		// The e2e fixtures, environment readers, and signer are shared with
		// the ws extension, and the command contract with the pubsub client, at
		// the source level: one file each, no copies.
		alias: SOURCE_ALIASES,
	},
});
