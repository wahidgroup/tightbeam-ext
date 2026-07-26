import { describe, expect, it } from "vitest";

import type { GateVerdict } from "./gate.js";
import { TopicGate } from "./gate.js";

/**
 * Feed `orders` through a fresh gate as delivered updates (classify,
 * then commit) and collect the verdicts. Advance is monotonic, so a
 * stale stamp never moves the baseline.
 */
function verdicts(orders: readonly bigint[]): GateVerdict[] {
	const gate = new TopicGate();
	return orders.map((order) => {
		const verdict = gate.classify(order);

		gate.advance(order);

		return verdict;
	});
}

const SEQUENCES = [
	{
		label: "a dense sequence is fresh throughout",
		orders: [1n, 2n, 3n],
		expected: ["fresh", "fresh", "fresh"],
	},
	{
		label: "a mid-stream join baselines on the first stamp",
		orders: [41n, 42n],
		expected: ["fresh", "fresh"],
	},
	{
		label: "a duplicate is stale",
		orders: [1n, 1n],
		expected: ["fresh", "stale"],
	},
	{
		label: "a reorder is stale and the sequence resumes",
		orders: [1n, 2n, 1n, 3n],
		expected: ["fresh", "fresh", "stale", "fresh"],
	},
	{
		label: "a jump is a gap and the stream continues from it",
		orders: [1n, 4n, 5n],
		expected: ["fresh", "gap", "fresh"],
	},
	{
		label: "a stale stamp does not move the baseline",
		orders: [5n, 3n, 6n],
		expected: ["fresh", "stale", "fresh"],
	},
] as const;

describe("TopicGate", () => {
	it.each(SEQUENCES)("$label", ({ orders, expected }) => {
		expect(verdicts(orders)).toEqual(expected);
	});

	it("exposes the next expected stamp once baselined", () => {
		const gate = new TopicGate();
		expect(gate.expected).toBeUndefined();

		gate.advance(7n);

		expect(gate.expected).toBe(8n);
	});

	it("re-baselines after a reset", () => {
		const gate = new TopicGate();
		gate.advance(10n);
		gate.reset();

		expect(gate.expected).toBeUndefined();
		expect(gate.classify(3n)).toBe("fresh");
	});

	it("keeps the baseline until advance commits the delivery", () => {
		const gate = new TopicGate();
		gate.advance(1n);

		expect(gate.classify(2n)).toBe("fresh");
		expect(gate.classify(2n)).toBe("fresh");
		expect(gate.classify(3n)).toBe("gap");

		gate.advance(2n);
		expect(gate.expected).toBe(3n);
	});
});
