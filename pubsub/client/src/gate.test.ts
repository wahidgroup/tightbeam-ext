import { describe, expect, it } from "vitest";

import type { GateVerdict, Stamp } from "./gate.js";
import { TopicGate } from "./gate.js";

/**
 * A verdict as the assertions read it: its kind, and the stamp a gap
 * expected.
 */
type Reading = { readonly kind: "fresh" | "stale" } | { readonly kind: "gap"; readonly expected: bigint };

/**
 * One action against a gate under test: classify an update and settle its
 * stamp as the delivery ends, or reset the gate.
 */
type Step =
	| { op: "deliver"; order: bigint; reads: Reading }
	| { op: "fail"; order: bigint; reads: Reading }
	| { op: "classify"; order: bigint; reads: Reading }
	| { op: "reset" };

const FRESH: Reading = { kind: "fresh" };

const STALE: Reading = { kind: "stale" };

/**
 * The reading of a gap that expected `expected`.
 */
function gapFrom(expected: bigint): Reading {
	const reading: Reading = { kind: "gap", expected };
	return reading;
}

/**
 * The reading of `verdict`.
 */
function read(verdict: GateVerdict): Reading {
	if (verdict.kind === "gap") {
		const reading = gapFrom(verdict.gap.expected);
		return reading;
	}

	const reading: Reading = { kind: verdict.kind };
	return reading;
}

/**
 * The stamp of `verdict`, which a stale verdict lacks.
 */
function stampOf(verdict: GateVerdict): Stamp {
	if (verdict.kind === "stale") {
		throw new Error("a stale verdict carries no stamp");
	}

	return verdict.stamp;
}

/**
 * Drive `steps` against a fresh gate, asserting each classification.
 */
function run(steps: readonly Step[]): void {
	const gate = new TopicGate();

	for (const step of steps) {
		if (step.op === "reset") {
			gate.reset();
			continue;
		}

		const verdict = gate.classify(step.order);
		expect(read(verdict)).toEqual(step.reads);
		if (verdict.kind === "stale" || step.op === "classify") {
			continue;
		}
		if (step.op === "deliver") {
			verdict.stamp.delivered();
			continue;
		}

		verdict.stamp.failed();
	}
}

const CASES: readonly { label: string; steps: readonly Step[] }[] = [
	{
		label: "a dense sequence is fresh throughout",
		steps: [
			{ op: "deliver", order: 1n, reads: FRESH },
			{ op: "deliver", order: 2n, reads: FRESH },
			{ op: "deliver", order: 3n, reads: FRESH },
		],
	},
	{
		label: "a mid-stream join baselines on the first stamp",
		steps: [
			{ op: "deliver", order: 41n, reads: FRESH },
			{ op: "deliver", order: 42n, reads: FRESH },
		],
	},
	{
		label: "a duplicate is stale",
		steps: [
			{ op: "deliver", order: 1n, reads: FRESH },
			{ op: "classify", order: 1n, reads: STALE },
		],
	},
	{
		label: "a reorder is stale and the sequence resumes",
		steps: [
			{ op: "deliver", order: 1n, reads: FRESH },
			{ op: "deliver", order: 2n, reads: FRESH },
			{ op: "classify", order: 1n, reads: STALE },
			{ op: "deliver", order: 3n, reads: FRESH },
		],
	},
	{
		label: "a jump is a gap from the next stamp, and the stream continues from it",
		steps: [
			{ op: "deliver", order: 1n, reads: FRESH },
			{ op: "deliver", order: 4n, reads: gapFrom(2n) },
			{ op: "deliver", order: 5n, reads: FRESH },
		],
	},
	{
		label: "a stale stamp does not move the baseline",
		steps: [
			{ op: "deliver", order: 5n, reads: FRESH },
			{ op: "classify", order: 3n, reads: STALE },
			{ op: "deliver", order: 6n, reads: FRESH },
		],
	},
	{
		label: "re-baselines after a reset",
		steps: [
			{ op: "deliver", order: 10n, reads: FRESH },
			{ op: "reset" },
			{ op: "deliver", order: 3n, reads: FRESH },
		],
	},
	{
		label: "keeps the baseline until a delivery commits its stamp",
		steps: [
			{ op: "deliver", order: 1n, reads: FRESH },
			{ op: "classify", order: 2n, reads: FRESH },
			{ op: "classify", order: 2n, reads: FRESH },
			{ op: "classify", order: 3n, reads: gapFrom(2n) },
			{ op: "deliver", order: 2n, reads: FRESH },
			{ op: "classify", order: 4n, reads: gapFrom(3n) },
		],
	},
	{
		label: "reveals a failed first delivery as a gap from its stamp",
		steps: [
			{ op: "fail", order: 1n, reads: FRESH },
			{ op: "deliver", order: 2n, reads: gapFrom(1n) },
			{ op: "classify", order: 4n, reads: gapFrom(3n) },
		],
	},
	{
		label: "keeps a failed stamp retryable as fresh",
		steps: [
			{ op: "fail", order: 1n, reads: FRESH },
			{ op: "classify", order: 1n, reads: FRESH },
		],
	},
	{
		label: "reveals the loss from the lowest failed stamp",
		steps: [
			{ op: "fail", order: 2n, reads: FRESH },
			{ op: "fail", order: 1n, reads: FRESH },
			{ op: "classify", order: 3n, reads: gapFrom(1n) },
		],
	},
	{
		label: "ignores a failed stamp once a baseline exists",
		steps: [
			{ op: "deliver", order: 1n, reads: FRESH },
			{ op: "fail", order: 3n, reads: gapFrom(2n) },
			{ op: "classify", order: 4n, reads: gapFrom(2n) },
		],
	},
	{
		label: "forgets a failed stamp on reset",
		steps: [{ op: "fail", order: 4n, reads: FRESH }, { op: "reset" }, { op: "classify", order: 9n, reads: FRESH }],
	},
];

describe("TopicGate", () => {
	it.each(CASES)("$label", ({ steps }) => {
		run(steps);
	});

	it("a stamp settles once, so a later settlement of it moves nothing", () => {
		const gate = new TopicGate();
		const first = stampOf(gate.classify(1n));

		first.failed();
		first.delivered();

		expect(read(gate.classify(2n))).toEqual(gapFrom(1n));
	});

	it("a stamp classified before a reset settles nothing", () => {
		const gate = new TopicGate();
		const lost = stampOf(gate.classify(5n));

		gate.reset();
		lost.delivered();

		expect(read(gate.classify(1n))).toEqual(FRESH);
	});
});
