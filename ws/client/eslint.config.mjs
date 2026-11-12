import { defineConfig } from "eslint/config";
import base from "@wahidgroup/lint-rules/eslint/base";

import { realDependencies } from "../../scripts/eslint/real-dependencies.mjs";

/**
 * The specifiers of the wasm-pack glue, as gitignore patterns, where `\#wasm` escapes the leading `#` of a comment. A
 * value import of one would load the binary as the package loads, so the build section of `docs/ws-wasm.md` holds the
 * glue to the two engine loaders.
 */
const GLUE = ["\\#wasm", "**/wasm/*", "**/wasm-node/*"];

/**
 * The value import of the glue, which every module but the two engine loaders
 * refuses.
 */
const GLUE_IMPORT = {
	group: GLUE,
	allowTypeImports: true,
	message: "Reach the glue through Engine: Engine.load loads it.",
};

/**
 * The `no-restricted-syntax` entries of the shared base. A rule set again
 * replaces its earlier options, so the glue rule extends these.
 */
const BASE_SYNTAX = base.map((config) => config.rules?.["no-restricted-syntax"]).find((rule) => rule !== undefined);

export default defineConfig(
	...base,
	realDependencies,
	{
		// The wasm-pack build writes these bindings.
		ignores: ["wasm/", "wasm-node/"],
	},
	{
		rules: {
			"@typescript-eslint/no-restricted-imports": ["error", { patterns: [GLUE_IMPORT] }],
		},
	},
	{
		files: ["src/**/*.ts"],
		ignores: ["src/engine/**"],
		rules: {
			"no-restricted-syntax": [
				...BASE_SYNTAX,
				{
					selector: "ImportExpression",
					message: "Only the engine loaders import dynamically: Engine.load loads the glue.",
				},
			],
		},
	},
);
