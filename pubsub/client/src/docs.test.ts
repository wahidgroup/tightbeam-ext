import { describe, expect, it } from "vitest";

import { DocSamples } from "../../../scripts/vitest/doc-samples.mjs";

/**
 * The compile of each sample under the options of the package, with the
 * package read from its sources.
 */
const samples = new DocSamples({
	suite: import.meta.url,
	tsconfig: "../tsconfig.json",
	sources: { "@wahidgroup/tightbeam-pubsub-client": "./index.ts" },
});

/**
 * Each page that holds samples of the client, with the prelude of the names
 * that its samples take from their surroundings.
 */
const PAGES = [
	{
		page: "../README.md",
		prelude: "../doc-samples/README.d.ts",
	},
	{
		page: "../../../docs/pubsub-client.md",
		prelude: "../doc-samples/pubsub-client.d.ts",
	},
	{
		page: "../../../docs/pubsub.md",
		prelude: "../doc-samples/pubsub.d.ts",
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
