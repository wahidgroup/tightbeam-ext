/**
 * The eslint config of the repo scripts, which `make format-scripts` runs: docs/development.md (Targets).
 */
import { createRequire } from "node:module";
import { join } from "node:path";
import { env } from "node:process";
import { pathToFileURL } from "node:url";

/**
 * The npm project whose lint-rules base this config imports. The scripts belong to no npm project, so the Makefile
 * names it.
 */
const toolingRoot = env.TOOLING_ROOT;
if (toolingRoot === undefined) {
	throw new Error("scripts/eslint.config.mjs reads TOOLING_ROOT, which make format-scripts sets");
}

const tooling = createRequire(join(toolingRoot, "package.json"));
const { default: base } = await import(pathToFileURL(tooling.resolve("@wahidgroup/lint-rules/eslint/base")).href);

export default base;
