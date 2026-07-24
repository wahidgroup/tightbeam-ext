/**
 * Per-topic ordering over the dense `metadata.order` stamps the registry
 * assigns.
 *
 * The registry stamps 1, 2, 3, ... per topic, and each subscriber's
 * delivery lane emits sequentially, so the gate can classify every
 * arriving update against the last admitted stamp.
 */

/**
 * How one update relates to the admitted sequence.
 */
export type GateVerdict = "fresh" | "stale" | "gap";

/**
 * Classifies update stamps for one topic.
 *
 * The first update after construction (or {@link reset}) baselines the
 * sequence: a subscriber joining mid-stream accepts wherever the topic
 * currently is.
 */
export class TopicGate {
	private last: bigint | undefined;

	/**
	 * Classify `order` and advance the baseline.
	 *
	 * - `fresh`: the first update, or the next dense stamp.
	 * - `stale`: at or behind the baseline (a duplicate or reorder);
	 *   the baseline does not move.
	 * - `gap`: ahead by more than one, meaning updates were dropped.
	 *   The baseline advances to `order`, so the stream continues from
	 *   what actually arrived.
	 */
	admit(order: bigint): GateVerdict {
		if (this.last === undefined) {
			this.last = order;
			return "fresh";
		}
		if (order <= this.last) {
			return "stale";
		}

		const expected = this.last + 1n;

		this.last = order;

		if (order === expected) {
			return "fresh";
		}

		return "gap";
	}

	/**
	 * The next stamp that would classify as `fresh`, or `undefined`
	 * before the baseline exists.
	 */
	get expected(): bigint | undefined {
		if (this.last === undefined) {
			return undefined;
		}

		return this.last + 1n;
	}

	/**
	 * Forget the baseline: the next update re-baselines, as on a fresh
	 * subscription. Called on reattach.
	 */
	reset(): void {
		this.last = undefined;
	}
}
