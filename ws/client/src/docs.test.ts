import { describe, expect, it } from "vitest";

import { DocSamples } from "../../../scripts/vitest/doc-samples.mjs";

/**
 * The compile of each sample in the project of the published declarations,
 * which reads the package through its exports.
 */
const samples = new DocSamples({
	suite: import.meta.url,
	tsconfig: "../published/tsconfig.json",
});

/**
 * Each page that holds samples of the client, with the prelude of the names
 * that its samples take from their surroundings.
 */
const PAGES = [
	{ page: "../README.md" },
	{
		page: "../../../docs/ws-client.md",
		prelude: "../doc-samples/ws-client.d.ts",
	},
];

describe("page samples", () => {
	it.each(PAGES)(
		"$page compiles every ts sample",
		({ page, prelude }) => {
			const diagnostics = samples.diagnostics({ page, prelude });
			expect(diagnostics).toEqual([]);
		},
		60_000,
	);
});
