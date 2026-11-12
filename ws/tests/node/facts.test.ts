import { describe, expect, it } from "vitest";

import { DialFacts, StackFacts } from "../fixtures.js";

/**
 * Stack facts that differ in every field, so a page that swaps two of them
 * reads back other facts.
 */
const SOURCE: Readonly<Record<string, string>> = {
	MUX_STREAMS: "6",
	TBWS_DEMO_PAYMENT: "facts-test-payment",
	TBWS_MUX_BUDGET_C2S: "5000",
	TBWS_MUX_BUDGET_S2C: "7000",
};

/**
 * The facts of `source`, under the origin of this suite.
 */
function factsOf(source: Readonly<Record<string, string>>): StackFacts {
	const facts = StackFacts.over((name) => source[name], "the facts suite");
	return facts;
}

/**
 * The dial facts of {@link SOURCE}.
 */
const FACTS = DialFacts.read(factsOf(SOURCE));

/**
 * The query string of a page that a spec opens with `facts`.
 */
function pageQuery(facts: DialFacts): string {
	const params = new URLSearchParams(facts.params());
	const query = `?${params.toString()}`;
	return query;
}

describe("stack fact readers", () => {
	it.each(["", "eight", "-1", "8.5", " 8", "1e3"])("refuses the count %j, which is no whole number", (text) => {
		const facts = factsOf({ MUX_STREAMS: text });
		const parse = (): number => facts.count("MUX_STREAMS");
		expect(parse).toThrow("MUX_STREAMS");
	});

	it("reads a whole-number count", () => {
		const facts = factsOf({ MUX_STREAMS: "8" });
		expect(facts.count("MUX_STREAMS")).toBe(8);
	});

	it("reads every dial fact under its own name", () => {
		expect(FACTS.streams).toBe(6);
		expect(FACTS.paywall.payment).toBe("facts-test-payment");
		expect(FACTS.paywall.budgets).toEqual({
			clientToServer: 5_000,
			serverToClient: 7_000,
		});
	});

	it("reads back on a page the dial facts its spec opened it with", () => {
		const read = DialFacts.fromQuery(pageQuery(FACTS));
		expect(read).toEqual(FACTS);
	});

	it("refuses a page whose query lacks a dial fact", () => {
		const read = (): DialFacts => DialFacts.fromQuery("?MUX_STREAMS=8");
		expect(read).toThrow("TBWS_DEMO_PAYMENT");
	});
});
