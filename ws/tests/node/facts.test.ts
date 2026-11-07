import { describe, expect, it } from "vitest";

import type { DialFacts } from "../fixtures.js";
import {
	dialFactParams,
	parseCount,
	queryFacts,
	readDialFacts,
} from "../fixtures.js";

/**
 * Dial facts that differ in every field, so a page that swaps two of them
 * reads back other facts.
 */
const FACTS: DialFacts = {
	streams: 6,
	paywall: {
		payment: "facts-test-payment",
		budgets: { clientToServer: 5_000, serverToClient: 7_000 },
	},
};

/**
 * The query string of a page that a spec opens with `facts`.
 */
function pageQuery(facts: DialFacts): string {
	const params = new URLSearchParams(dialFactParams(facts));
	const query = `?${params.toString()}`;
	return query;
}

describe("stack fact readers", () => {
	it.each(["", "eight", "-1", "8.5", " 8", "1e3"])(
		"refuses the count %j, which is no whole number",
		(text) => {
			const parse = (): number => parseCount("MUX_STREAMS", text);
			expect(parse).toThrow("MUX_STREAMS");
		},
	);

	it("reads a whole-number count", () => {
		expect(parseCount("MUX_STREAMS", "8")).toBe(8);
	});

	it("reads back on a page the dial facts its spec opened it with", () => {
		const source = queryFacts(pageQuery(FACTS));
		const read = readDialFacts(source);
		expect(read).toEqual(FACTS);
	});

	it("refuses a page whose query lacks a dial fact", () => {
		const source = queryFacts("?MUX_STREAMS=8");
		const read = (): DialFacts => readDialFacts(source);
		expect(read).toThrow("TBWS_DEMO_PAYMENT");
	});
});
