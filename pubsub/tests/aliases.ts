/**
 * The source-level aliases of the pubsub e2e suites. The `paths` of
 * tsconfig.json are their one home: the type checker reads them there, and
 * Vite and Vitest read them through {@link SOURCE_ALIASES}.
 */

import { resolve } from "node:path";

import tsconfig from "./tsconfig.json" with { type: "json" };

/**
 * Each alias of the tsconfig `paths`, resolved to the absolute file of its
 * first target. Every alias here names one exact file, so the map holds no
 * wildcard patterns.
 */
export const SOURCE_ALIASES: Record<string, string> = {};

for (const [alias, targets] of Object.entries(tsconfig.compilerOptions.paths)) {
	const [target] = targets;
	if (target !== undefined) {
		SOURCE_ALIASES[alias] = resolve(import.meta.dirname, target);
	}
}
