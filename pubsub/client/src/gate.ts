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
 *
 * Invariant: every stamp the gate sees is committed through
 * {@link advance} or revealed as a `gap`. After the first delivery,
 * the baseline covers losses. Before one, {@link witness} records the
 * undelivered stamp so the next higher stamp classifies as a `gap`.
 */
export class TopicGate {
	private last: bigint | undefined;

	private witnessed: bigint | undefined;

	/**
	 * Classify `order` against the baseline without moving it.
	 *
	 * - `fresh`: the first update, or the next dense stamp.
	 * - `stale`: at or behind the baseline (a duplicate or reorder).
	 * - `gap`: ahead by more than one, meaning updates were dropped.
	 */
	classify(order: bigint): GateVerdict {
		if (this.last === undefined) {
			if (this.witnessed !== undefined && order > this.witnessed) {
				return "gap";
			}

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

		this.witnessed = undefined;
	}

	/**
	 * Record a stamp seen before any baseline exists. The next higher
	 * stamp then classifies as a `gap`. The lowest stamp wins. Once a
	 * baseline exists, later losses use the baseline, so this record is
	 * pre-baseline only.
	 */
	witness(order: bigint): void {
		if (this.last !== undefined) {
			return;
		}
		if (this.witnessed === undefined || order < this.witnessed) {
			this.witnessed = order;
		}
	}

	/**
	 * The next stamp that would classify as `fresh`. After a baseline,
	 * that is baseline plus one. Before one, that is the witnessed
	 * undelivered stamp, or `undefined` when the gate has seen nothing.
	 */
	get expected(): bigint | undefined {
		if (this.last !== undefined) {
			return this.last + 1n;
		}

		return this.witnessed;
	}

	/**
	 * Clear the baseline and any witnessed stamp so the next one
	 * classifies as `fresh`.
	 */
	reset(): void {
		this.last = undefined;
		this.witnessed = undefined;
	}
}
