import { describe, expect, it } from "vitest";

import type { Frame } from "@wahidgroup/tightbeam-ws-client";
import { Engine } from "@wahidgroup/tightbeam-ws-client";

import type { Gap } from "./gate.js";
import type { Entry, GapHandler, SubscribeOptions } from "./manager.js";
import { DeferralBudget, Delivery, Entries, MAX_DEFERRED, PayloadShape } from "./manager.js";
import { CONTENT_TYPE, codecNaming } from "./testing/codecs.js";
import { Topic } from "./topic.js";

/**
 * The owners of a subscription that need no peer, over frames that the real engine builds.
 * The node lane of `pubsub/tests` runs each behavior that needs a peer, against the real relay.
 */

/**
 * The engine that builds and decodes every frame in this suite.
 */
const engine = await Engine.load();

/**
 * The topic of every entry in this suite.
 */
const PRICES = Topic.parse("prices");

/**
 * The body of every update in this suite.
 */
const EMPTY_BODY = new Uint8Array(0);

/**
 * What the application of an entry receives, in the order it does: the stamp
 * of each delivered update, and each gap its gap observer receives.
 */
type Event = bigint | readonly ["gap", bigint, bigint];

/**
 * The subscribe options of an entry whose deliveries and gaps land in
 * `events`.
 */
type Recording = SubscribeOptions<Uint8Array> & { readonly onGap: GapHandler };

/**
 * The options of an entry whose deliveries and gaps land in `events`.
 */
function recording(events: Event[]): Recording {
	const options = {
		codec: engine.opaque,
		onUpdate: (_message: Uint8Array, update: Frame): void => {
			events.push(update.order);
		},
		onGap: (_topic: Topic, gap: Gap): void => {
			events.push(["gap", gap.expected, gap.received]);
		},
	};
	return options;
}

/**
 * The entry of {@link PRICES} that `entries` opens under `options`.
 */
function openPrices(entries: Entries, options: Recording): Entry {
	const delivery = Delivery.of(PRICES, options, engine);
	const observers = { onGap: options.onGap, onEnd: options.onEnd };
	const entry = entries.open(PRICES, delivery, observers);
	return entry;
}

/**
 * A live entry of {@link PRICES}: its `sub/` left, and the server
 * acknowledged it.
 */
function livePrices(entries: Entries, options: Recording): Entry {
	const entry = openPrices(entries, options);
	entry.leaving();
	entry.acknowledged();
	return entry;
}

/**
 * The update the registry pushes on {@link PRICES} with the stamp `order`.
 */
async function update(order: number): Promise<Frame> {
	const empty = engine.frameBuilder(EMPTY_BODY);
	const stamped = empty.withId(PRICES.name).withOrder(order);
	const built = await stamped.build();
	return built;
}

/**
 * One answer the test settles by hand.
 */
interface Held {
	readonly answer: Promise<void>;
	readonly settle: () => void;
}

/**
 * An answer that stays open until the test settles it.
 */
function held(): Held {
	let settle = (): void => undefined;
	const answer = new Promise<void>((resolve) => {
		settle = (): void => {
			resolve();
		};
	});

	return { answer, settle };
}

/**
 * Await `pending`, then record `mark` in `marks`, so a test reads the order
 * in which its promises settled.
 */
async function marking(pending: Promise<void>, marks: string[], mark: string): Promise<void> {
	await pending;
	marks.push(mark);
}

/**
 * The options of an entry whose handler waits for `holding` on the update
 * stamped `stalled`, and whose deliveries and gaps land in `events`.
 */
function stalling(events: Event[], stalled: bigint, holding: Held): Recording {
	const options = {
		...recording(events),
		onUpdate: async (_message: Uint8Array, update: Frame): Promise<void> => {
			if (update.order === stalled) {
				await holding.answer;
			}

			events.push(update.order);
		},
	};
	return options;
}

/**
 * The options of an entry whose handler throws on the update stamped
 * `poisoned`, and whose deliveries and gaps land in `events`.
 */
function poisoning(events: Event[], poisoned: bigint): Recording {
	const options = {
		...recording(events),
		onUpdate: (_message: Uint8Array, update: Frame): void => {
			if (update.order === poisoned) {
				throw new Error("poisoned update");
			}

			events.push(update.order);
		},
	};
	return options;
}

/**
 * A budget whose every slot is drawn, with the first slot it gave out.
 */
function drained(): { budget: DeferralBudget; first: Disposable } {
	const budget = new DeferralBudget();
	const first = budget.draw();
	if (first === undefined) {
		throw new Error("an empty budget refused its first draw");
	}

	for (let drawn = 1; drawn < MAX_DEFERRED; drawn += 1) {
		budget.draw();
	}

	return { budget, first };
}

/**
 * An earlier entry of {@link PRICES} that ended one way, so a newer entry
 * holds the topic.
 */
interface EarlierEnding {
	readonly ending: string;
	readonly end: (entries: Entries, earlier: Entry) => Promise<void>;
}

/**
 * Every way an earlier entry ends while a newer one may follow it.
 */
const EARLIER_ENDINGS: readonly EarlierEnding[] = [
	{
		ending: "unsubscribed",
		end: async (entries, earlier) => {
			entries.end(earlier);
		},
	},
	{
		ending: "completed",
		end: (_entries, earlier) => earlier.complete(0n),
	},
	{
		ending: "refused on replay",
		end: async (_entries, earlier) => {
			earlier.lapse();
			earlier.leaving();
			earlier.refused();
		},
	},
];

describe("PayloadShape", () => {
	it("a decoding shape decodes an update after the caller frees its codec contentOid", async () => {
		const contentOid = engine.oid(CONTENT_TYPE);
		const payload = { codec: codecNaming(engine, contentOid) };
		const shape = PayloadShape.decoding(payload, engine);

		contentOid.free();

		const pushed = await update(1);
		await expect(shape.decode(pushed)).resolves.toEqual(EMPTY_BODY);
	});
});

describe("DeferralBudget", () => {
	it("refuses a draw once every slot is held", () => {
		const { budget } = drained();

		expect(budget.draw()).toBeUndefined();
	});

	it("a slot returns once, however often it is disposed", () => {
		const { budget, first } = drained();

		first[Symbol.dispose]();
		first[Symbol.dispose]();

		expect(budget.draw()).toBeDefined();
		expect(budget.draw()).toBeUndefined();
	});
});

describe("Entry gaps", () => {
	it("hands a gap to its observer before it delivers the revealing update", async () => {
		const events: Event[] = [];
		const entry = livePrices(new Entries(), recording(events));

		await entry.receive(await update(1));
		await entry.receive(await update(3));

		expect(events).toEqual([1n, ["gap", 2n, 3n], 3n]);
	});

	it("delivers a stamp that arrives while the gap answer runs, in order", async () => {
		const events: Event[] = [];
		const answering = held();
		const options = {
			...recording(events),
			onGap: async (_topic: Topic, gap: Gap) => {
				events.push(["gap", gap.expected, gap.received]);
				await answering.answer;
			},
		};
		const entry = livePrices(new Entries(), options);
		await entry.receive(await update(1));

		const revealing = entry.receive(await update(3));
		await entry.receive(await update(2));
		answering.settle();
		await revealing;

		expect(events).toEqual([1n, ["gap", 2n, 3n], 2n, 3n]);
	});

	it("reveals a failed delivery as a gap on the next update", async () => {
		const events: Event[] = [];
		const entry = livePrices(new Entries(), poisoning(events, 1n));

		const failed = entry.receive(await update(1));
		await expect(failed).rejects.toThrow("poisoned update");
		await entry.receive(await update(2));

		expect(events).toEqual([["gap", 1n, 2n], 2n]);
	});

	it("a lapsed entry re-baselines, so its replay delivers the first stamp again", async () => {
		const events: Event[] = [];
		const entry = livePrices(new Entries(), recording(events));
		await entry.receive(await update(1));

		const replayed = entry.lapse();
		entry.leaving();
		entry.acknowledged();

		await entry.receive(await update(1));

		expect(replayed?.id).toBe("sub/prices");
		expect(events).toEqual([1n, 1n]);
	});

	it("a delivery of the lost connection leaves the baseline of the replay alone", async () => {
		const events: Event[] = [];
		const stalled = held();
		const entry = livePrices(new Entries(), stalling(events, 5n, stalled));

		const lost = entry.receive(await update(5));
		entry.lapse();
		entry.leaving();
		entry.acknowledged();
		stalled.settle();
		await lost;

		await entry.receive(await update(1));

		expect(events).toEqual([5n, 1n]);
	});
});

describe("Entry completion", () => {
	it("reports the trailing updates that the end of its topic reveals as a gap", async () => {
		const events: Event[] = [];
		const ended: string[] = [];
		const options = {
			...recording(events),
			onEnd: (topic: Topic): void => {
				ended.push(topic.name);
			},
		};
		const entries = new Entries();
		const entry = livePrices(entries, options);
		await entry.receive(await update(1));

		await entry.complete(3n);

		expect(events).toEqual([1n, ["gap", 2n, 4n]]);
		expect(entry.state).toBe("ended");
		expect(ended).toEqual(["prices"]);
	});

	it("completes at its baseline with no gap", async () => {
		const events: Event[] = [];
		const entries = new Entries();
		const entry = livePrices(entries, recording(events));
		await entry.receive(await update(1));
		await entry.receive(await update(2));

		await entry.complete(2n);

		expect(events).toEqual([1n, 2n]);
		expect(entry.state).toBe("ended");
	});
});

describe("Entry reattach", () => {
	it("a deferred entry re-baselines on reattach, so the restarted counter delivers", async () => {
		const events: Event[] = [];
		const entry = openPrices(new Entries(), recording(events));
		entry.leaving();
		await entry.receive(await update(5));
		entry.deferred();

		const replayed = entry.lapse();
		entry.leaving();
		entry.acknowledged();
		await entry.receive(await update(1));

		expect(replayed).toBeUndefined();
		expect(events).toEqual([5n, 1n]);
	});
});

describe("Entry states", () => {
	it("a pending entry goes live on the acknowledgment", () => {
		const entry = openPrices(new Entries(), recording([]));
		entry.leaving();
		entry.acknowledged();
		expect(entry.state).toBe("live");
	});

	it("a lost sub/ defers a pending entry, and its replay makes it pending again", () => {
		const entry = openPrices(new Entries(), recording([]));
		entry.leaving();
		entry.deferred();

		const deferred = entry.state;

		entry.leaving();

		expect(deferred).toBe("deferred");
		expect(entry.state).toBe("pending");
	});

	it("an entry that is not live lapses with no sub/ to replay", () => {
		const entry = openPrices(new Entries(), recording([]));
		entry.leaving();

		expect(entry.lapse()).toBeUndefined();
		expect(entry.state).toBe("pending");
	});

	it("a refused pending entry ends and leaves its topic to a later entry", () => {
		const entries = new Entries();
		const refused = openPrices(entries, recording([]));
		refused.leaving();
		refused.refused();

		const later = livePrices(entries, recording([]));
		expect(refused.state).toBe("ended");
		expect(later.state).toBe("live");
		expect(entries.names).toEqual(["prices"]);
	});

	it("an ended entry wants no later sub/", () => {
		const entries = new Entries();
		const entry = livePrices(entries, recording([]));
		entries.end(entry);
		expect(entry.wants()).toBe(false);
	});

	it("an entry ended before its first sub/ left still sends it, and wants no later one", () => {
		const entries = new Entries();
		const entry = openPrices(entries, recording([]));
		entries.end(entry);

		const owed = entry.wants();
		entry.leaving();

		expect(entry.state).toBe("ended");
		expect(owed).toBe(true);
		expect(entry.wants()).toBe(false);
	});

	it.each(EARLIER_ENDINGS)("the release of an earlier entry $ending leaves a newer entry live", async ({ end }) => {
		const entries = new Entries();
		const earlier = livePrices(entries, recording([]));
		await end(entries, earlier);
		const newer = livePrices(entries, recording([]));

		const released = entries.end(earlier);

		expect(released).toBe(false);
		expect(newer.state).toBe("live");
	});

	it("a completion ends the entry and tells its end observer", async () => {
		const ended: string[] = [];
		const options = {
			...recording([]),
			onEnd: (topic: Topic): void => {
				ended.push(topic.name);
			},
		};

		const entries = new Entries();
		const entry = livePrices(entries, options);
		await entry.complete(0n);
		expect(entry.state).toBe("ended");
		expect(entries.names).toEqual([]);
		expect(ended).toEqual(["prices"]);
	});

	it("a completion of a replaced entry tells no end observer and leaves the newer entry live", async () => {
		const ended: string[] = [];
		const options = {
			...recording([]),
			onEnd: (topic: Topic): void => {
				ended.push(topic.name);
			},
		};

		const entries = new Entries();
		const earlier = livePrices(entries, options);
		entries.end(earlier);
		const newer = livePrices(entries, recording([]));

		await earlier.complete(0n);

		expect(newer.state).toBe("live");
		expect(ended).toEqual([]);
	});
});

describe("Entry settlement", () => {
	it("an ended entry with no delivery in flight is settled", async () => {
		const entries = new Entries();
		const entry = livePrices(entries, recording([]));
		entries.end(entry);

		await expect(entry.settled()).resolves.toBeUndefined();
	});

	it("an entry ended mid-delivery settles after that delivery does", async () => {
		const started = held();
		const released = held();
		const settlement: string[] = [];
		const options = {
			...recording([]),
			onUpdate: async (): Promise<void> => {
				started.settle();
				await released.answer;
				settlement.push("handled");
			},
		};
		const entries = new Entries();
		const entry = livePrices(entries, options);

		const delivering = entry.receive(await update(1));
		await started.answer;
		entries.end(entry);
		const settling = marking(entry.settled(), settlement, "settled");
		released.settle();

		await Promise.all([delivering, settling]);

		expect(settlement).toEqual(["handled", "settled"]);
	});
});
