import { describe, expect, it } from "vitest";

import type { GateVerdict } from "./gate.js";
import { TopicGate } from "./gate.js";

/**
 * One action against a gate under test.
 */
type Step =
	| { op: "classify"; order: bigint; expect: GateVerdict }
	| { op: "advance"; order: bigint }
	| { op: "witness"; order: bigint }
	| { op: "expected"; value: bigint | undefined }
	| { op: "reset" };

/**
 * Drive `steps` against a fresh gate. Delivered paths use classify then
 * advance. Witness paths record undelivered stamps before a baseline.
 */
function run(steps: readonly Step[]): void {
	const gate = new TopicGate();

	for (const step of steps) {
		if (step.op === "classify") {
			expect(gate.classify(step.order)).toBe(step.expect);
			continue;
		}
		if (step.op === "advance") {
			gate.advance(step.order);
			continue;
		}
		if (step.op === "witness") {
			gate.witness(step.order);
			continue;
		}
		if (step.op === "expected") {
			expect(gate.expected).toBe(step.value);
			continue;
		}

		gate.reset();
	}
}

/**
 * Dense delivered sequences: each order is classified then committed.
 */
function delivered(
	orders: readonly bigint[],
	expected: readonly GateVerdict[],
): Step[] {
	expect(orders.length).toBe(expected.length);

	const steps: Step[] = [];
	for (const [index, order] of orders.entries()) {
		const verdict = expected[index];
		if (verdict === undefined) {
			expect.fail(`missing expected verdict at index ${index}`);
			return steps;
		}

		steps.push({ op: "classify", order, expect: verdict });
		steps.push({ op: "advance", order });
	}

	return steps;
}

const CASES = [
	{
		label: "a dense sequence is fresh throughout",
		steps: delivered([1n, 2n, 3n], ["fresh", "fresh", "fresh"]),
	},
	{
		label: "a mid-stream join baselines on the first stamp",
		steps: delivered([41n, 42n], ["fresh", "fresh"]),
	},
	{
		label: "a duplicate is stale",
		steps: delivered([1n, 1n], ["fresh", "stale"]),
	},
	{
		label: "a reorder is stale and the sequence resumes",
		steps: delivered(
			[1n, 2n, 1n, 3n],
			["fresh", "fresh", "stale", "fresh"],
		),
	},
	{
		label: "a jump is a gap and the stream continues from it",
		steps: delivered([1n, 4n, 5n], ["fresh", "gap", "fresh"]),
	},
	{
		label: "a stale stamp does not move the baseline",
		steps: delivered([5n, 3n, 6n], ["fresh", "stale", "fresh"]),
	},
	{
		label: "exposes the next expected stamp once baselined",
		steps: [
			{ op: "expected", value: undefined },
			{ op: "advance", order: 7n },
			{ op: "expected", value: 8n },
		],
	},
	{
		label: "re-baselines after a reset",
		steps: [
			{ op: "advance", order: 10n },
			{ op: "reset" },
			{ op: "expected", value: undefined },
			{ op: "classify", order: 3n, expect: "fresh" },
		],
	},
	{
		label: "keeps the baseline until advance commits the delivery",
		steps: [
			{ op: "advance", order: 1n },
			{ op: "classify", order: 2n, expect: "fresh" },
			{ op: "classify", order: 2n, expect: "fresh" },
			{ op: "classify", order: 3n, expect: "gap" },
			{ op: "advance", order: 2n },
			{ op: "expected", value: 3n },
		],
	},
	{
		label: "reveals a loss before any baseline through a witnessed stamp",
		steps: [
			{ op: "witness", order: 1n },
			{ op: "expected", value: 1n },
			{ op: "classify", order: 2n, expect: "gap" },
			{ op: "advance", order: 2n },
			{ op: "expected", value: 3n },
		],
	},
	{
		label: "keeps a witnessed stamp retryable as fresh",
		steps: [
			{ op: "witness", order: 1n },
			{ op: "classify", order: 1n, expect: "fresh" },
		],
	},
	{
		label: "remembers the lowest witnessed stamp",
		steps: [
			{ op: "witness", order: 2n },
			{ op: "witness", order: 1n },
			{ op: "expected", value: 1n },
		],
	},
	{
		label: "ignores a witness once the baseline exists",
		steps: [
			{ op: "advance", order: 1n },
			{ op: "witness", order: 3n },
			{ op: "expected", value: 2n },
		],
	},
	{
		label: "clears the witnessed stamp on reset",
		steps: [
			{ op: "witness", order: 4n },
			{ op: "reset" },
			{ op: "expected", value: undefined },
			{ op: "classify", order: 9n, expect: "fresh" },
		],
	},
] as const;

describe("TopicGate", () => {
	it.each(CASES)("$label", ({ steps }) => {
		run(steps);
	});
});
