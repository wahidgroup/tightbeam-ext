/**
 * The ordering gate of one subscription. The page `docs/pubsub-client.md`
 * (Ordering and gaps) states each verdict.
 */

/**
 * The stamp of one classified update, which its delivery settles once.
 *
 * - {@link delivered} commits the stamp as the baseline.
 * - {@link failed} witnesses it, so the next higher stamp reveals the loss as
 *   a `gap` even before any baseline.
 * - The first settlement wins.
 * - {@link TopicGate.reset} states which stamps settle nothing.
 */
export interface Stamp {
	/**
	 * The `metadata.order` of the update.
	 */
	readonly order: bigint;

	/**
	 * Commit the stamp: the update reached the application.
	 */
	delivered(): void;

	/**
	 * Witness the stamp: the decode or the handler of the update failed.
	 */
	failed(): void;
}

/**
 * The updates that one subscription lost, which an arrival past the next
 * awaited order reveals.
 */
export interface Gap {
	/**
	 * The next order the gate awaited, the first one lost.
	 */
	readonly expected: bigint;

	/**
	 * The order that revealed the loss.
	 */
	readonly received: bigint;
}

/**
 * How one update relates to the committed sequence.
 *
 * - `fresh`: the first update, or the next dense stamp.
 * - `stale`: at or behind the baseline, such as a duplicate or a reorder.
 *   It carries no stamp, because it is not delivered.
 * - `gap`: past the next stamp the gate awaited, so the updates of its
 *   {@link Gap} from `expected` up to this one were lost.
 */
export type GateVerdict =
	| { readonly kind: "fresh"; readonly stamp: Stamp }
	| { readonly kind: "stale" }
	| {
			readonly kind: "gap";
			readonly gap: Gap;
			readonly stamp: Stamp;
	  };

/**
 * What the gate knows of the sequence.
 *
 * - `empty`: no stamp settled.
 * - `witnessed`: no delivery yet, and `lowest` is the lowest stamp whose
 *   delivery failed.
 * - `committed`: `last` is the highest delivered stamp.
 */
type Sequence =
	| { readonly kind: "empty" }
	| { readonly kind: "witnessed"; readonly lowest: bigint }
	| { readonly kind: "committed"; readonly last: bigint };

/**
 * The sequence of a gate that has settled nothing.
 */
const EMPTY: Sequence = { kind: "empty" };

/**
 * The one stamp implementation: it hands its outcome to the gate that
 * classified it, once.
 */
class SettledOnce implements Stamp {
	readonly order: bigint;

	/**
	 * The settlement still to run, or `undefined` once the stamp settled.
	 */
	#settle: ((delivered: boolean) => void) | undefined;

	constructor(order: bigint, settle: (delivered: boolean) => void) {
		this.order = order;
		this.#settle = settle;
	}

	delivered(): void {
		this.#take()?.(true);
	}

	failed(): void {
		this.#take()?.(false);
	}

	/**
	 * The settlement, which leaves the stamp settled.
	 */
	#take(): ((delivered: boolean) => void) | undefined {
		const settle = this.#settle;
		this.#settle = undefined;
		return settle;
	}
}

/**
 * Classifies update stamps for one topic.
 *
 * Classification moves nothing, and the {@link Stamp} of each update settles
 * once its delivery settles.
 */
export class TopicGate {
	#sequence: Sequence = EMPTY;

	/**
	 * The token of the current baseline, which {@link reset} replaces.
	 */
	#era: object = {};

	/**
	 * Classify `order` against the sequence without moving it.
	 */
	classify(order: bigint): GateVerdict {
		const sequence = this.#sequence;
		switch (sequence.kind) {
			case "empty": {
				const fresh = this.#fresh(order);
				return fresh;
			}
			case "witnessed": {
				if (order > sequence.lowest) {
					const gap = this.#gap({ expected: sequence.lowest, received: order });
					return gap;
				}

				const fresh = this.#fresh(order);
				return fresh;
			}
			case "committed": {
				const expected = sequence.last + 1n;
				if (order < expected) {
					return { kind: "stale" };
				}
				if (order === expected) {
					const fresh = this.#fresh(order);
					return fresh;
				}

				const gap = this.#gap({ expected, received: order });
				return gap;
			}
		}
	}

	/**
	 * Forget the sequence, so the next stamp classifies as `fresh`. Every
	 * stamp classified before the reset settles nothing.
	 */
	reset(): void {
		this.#sequence = EMPTY;
		this.#era = {};
	}

	#fresh(order: bigint): GateVerdict {
		const stamp = this.#stamp(order);
		const fresh: GateVerdict = { kind: "fresh", stamp };
		return fresh;
	}

	#gap(gap: Gap): GateVerdict {
		const stamp = this.#stamp(gap.received);
		const verdict: GateVerdict = { kind: "gap", gap, stamp };
		return verdict;
	}

	/**
	 * The stamp of `order`, bound to the current `#era`.
	 */
	#stamp(order: bigint): Stamp {
		const era = this.#era;
		const settle = (delivered: boolean): void => {
			if (this.#era !== era) {
				return;
			}

			if (delivered) {
				this.#sequence = this.#committed(order);
			} else {
				this.#sequence = this.#witnessed(order);
			}
		};

		const stamp = new SettledOnce(order, settle);
		return stamp;
	}

	/**
	 * The `committed` sequence once `order` is delivered.
	 */
	#committed(order: bigint): Sequence {
		const sequence = this.#sequence;
		if (sequence.kind === "committed" && sequence.last >= order) {
			return sequence;
		}

		const committed: Sequence = { kind: "committed", last: order };
		return committed;
	}

	/**
	 * The sequence once the delivery of `order` failed. A baseline already
	 * reveals later losses, so the witness counts only before one, and the
	 * lowest witnessed stamp wins.
	 */
	#witnessed(order: bigint): Sequence {
		const sequence = this.#sequence;
		if (sequence.kind === "committed") {
			return sequence;
		}
		if (sequence.kind === "witnessed" && sequence.lowest <= order) {
			return sequence;
		}

		const witnessed: Sequence = { kind: "witnessed", lowest: order };
		return witnessed;
	}
}
