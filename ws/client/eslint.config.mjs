import { defineConfig } from "eslint/config";
import base from "@wahidgroup/lint-rules/eslint/base";

import { realDependencies } from "../../scripts/eslint/real-dependencies.mjs";

/**
 * The specifiers of the wasm-pack glue. A value import of one would load the
 * binary when the package loads, so only the two engine loaders reach the
 * glue, through a dynamic import inside `load`. The groups are gitignore
 * patterns, where a leading `#` opens a comment, so `\#wasm` names the
 * specifier.
 */
const GLUE = ["\\#wasm", "**/wasm/*", "**/wasm-node/*"];

/**
 * The value import of the glue, which every module but the two engine loaders
 * refuses.
 */
const GLUE_IMPORT = {
	group: GLUE,
	allowTypeImports: true,
	message: "Reach the glue through Engine: TightbeamWsClient.init loads it.",
};

/**
 * The symbol keys of the package-internal statics that `client.ts` and
 * `errors.ts` declare. TypeScript has no visibility narrower than a package,
 * so only the modules that the override below names import them.
 */
const INTERNAL_KEY_IMPORT = {
	regex: "(^|/)(client|errors)\\.js$",
	importNames: ["OVER", "DECIDES", "BRANDED_CODE"],
	message:
		"Only Engine reads the internal statics: reach the client and the codes through Engine.",
};

/**
 * The `no-restricted-syntax` entries of the shared base. A rule set again
 * replaces its earlier options, so the glue rule extends these.
 */
const BASE_SYNTAX = base
	.map((config) => config.rules?.["no-restricted-syntax"])
	.find((rule) => rule !== undefined);

export default defineConfig(
	...base,
	realDependencies,
	{
		// wasm-pack generated bindings; not authored source.
		ignores: ["wasm/", "wasm-node/"],
	},
	{
		rules: {
			"@typescript-eslint/no-restricted-imports": [
				"error",
				{ patterns: [GLUE_IMPORT, INTERNAL_KEY_IMPORT] },
			],
		},
	},
	{
		// Engine builds the client over its socket and decides the codes, so it
		// alone imports the internal keys. A rule set again replaces its earlier
		// options, so the glue import stays refused here.
		files: ["src/engine.ts"],
		rules: {
			"@typescript-eslint/no-restricted-imports": [
				"error",
				{ patterns: [GLUE_IMPORT] },
			],
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
					message:
						"Only the engine loaders import dynamically: TightbeamWsClient.init loads the glue.",
				},
			],
		},
	},
);
