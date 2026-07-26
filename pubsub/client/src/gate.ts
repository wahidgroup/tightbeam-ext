/**
 * Per-topic ordering over the dense `metadata.order` stamps the registry
 * assigns.
 *
 * The registry stamps 1, 2, 3, ... per topic, and each subscriber's
 * delivery lane emits sequentially, so the gate can classify every
 * arriving update against the last committed stamp.
 */

/**
 * How one update relates to the committed sequence.
 */
export type GateVerdict = "fresh" | "stale" | "gap";

/**
 * Classifies update stamps for one topic.
 *
 * Classification is read-only. The baseline commits through
 * {@link advance} after a delivery settles, so a failed decode or
 * handler leaves the stamp unclaimed and a later update can surface
 * the loss as a `gap`.
 */
export class TopicGate {
	private last: bigint | undefined;

	/**
	 * Classify `order` against the baseline, without moving it.
	 *
	 * - `fresh`: the first update, or the next dense stamp.
	 * - `stale`: at or behind the baseline (a duplicate or reorder).
	 * - `gap`: ahead by more than one, meaning updates were dropped.
	 *
	 * The baseline commits separately through {@link advance}, after
	 * the update actually delivered: a failed decode or handler leaves
	 * the stamp unclaimed, so a redelivery stays `fresh` and the next
	 * stamp reveals the loss as a `gap`.
	 */
	classify(order: bigint): GateVerdict {
		if (this.last === undefined) {
			return "fresh";
		}
		if (order <= this.last) {
			return "stale";
		}
		if (order === this.last + 1n) {
			return "fresh";
		}

		return "gap";
	}

	/**
	 * Commit `order` as the delivered baseline. Monotonic: an older
	 * stamp never moves the baseline back.
	 */
	advance(order: bigint): void {
		if (this.last === undefined || order > this.last) {
			this.last = order;
		}
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
	 * Clear the baseline so the next stamp classifies as `fresh`.
	 */
	reset(): void {
		this.last = undefined;
	}
}
