import { describe, expect, it } from "vitest";

import type { GateVerdict } from "./gate.js";
import { TopicGate } from "./gate.js";

/**
 * Feed `orders` through a fresh gate and collect the verdicts.
 */
function verdicts(orders: readonly bigint[]): GateVerdict[] {
	const gate = new TopicGate();
	return orders.map((order) => gate.admit(order));
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

		gate.admit(7n);

		expect(gate.expected).toBe(8n);
	});

	it("re-baselines after a reset", () => {
		const gate = new TopicGate();
		gate.admit(10n);
		gate.reset();

		expect(gate.expected).toBeUndefined();
		expect(gate.admit(3n)).toBe("fresh");
	});
});
