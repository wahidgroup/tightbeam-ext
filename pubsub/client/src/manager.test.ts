import { describe, expect, expectTypeOf, it } from "vitest";

import type {
	Frame,
	MessageCodec,
	OidName,
} from "@wahidgroup/tightbeam-ws-client";
import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";

import type {
	ClientPorts,
	CommandLane,
	Entry,
	ManagerOptions,
	ServePort,
	SubscribeOptions,
} from "./manager.js";
import {
	Delivery,
	Entries,
	PayloadShape,
	SubscriptionManager,
} from "./manager.js";
import { Topic } from "./topic.js";

/**
 * The owners of a subscription that need no peer: the payload shape, the
 * entry and its gate, and the entries of a manager, over real frames that the
 * real engine builds. The node lane of `pubsub/tests` runs every behavior
 * that needs a peer against the real relay.
 */

/**
 * The engine that builds and decodes every frame in this suite.
 */
const engine = await TightbeamWsClient.init();

/**
 * The parameters the manager constructor takes.
 */
type ManagerArguments = [ClientPorts, ManagerOptions?];

/**
 * The method that moves a manager onto the ports of a new connection.
 */
type Reattach = SubscriptionManager["reattach"];

/**
 * Every public member of `ClientPorts`: its serve port, the engine it reads
 * from that port, and its lane factory.
 */
type PortsMembers = "serving" | "engine" | "lane";

/**
 * Every public member of `ServePort`: its one serve call, and the engine that
 * dialed the client.
 */
type ServeMembers = "serve" | "engine";

/**
 * Every public member of `CommandLane`: its topic, its idleness, its turns,
 * and the disposal that drops its deferred commands once its turns settle.
 */
type LaneMembers =
	"topic" | "idle" | "send" | "adopt" | typeof Symbol.asyncDispose;

/**
 * Every public member of `SubscriptionManager`: its topics, its commands, and
 * its disposal.
 */
type ManagerMembers =
	| "topics"
	| "subscribe"
	| "publish"
	| "unsubscribe"
	| "reattach"
	| typeof Symbol.asyncDispose;

/**
 * The topic of every entry in this suite.
 */
const PRICES = Topic.parse("prices");

/**
 * The body of every update in this suite.
 */
const EMPTY_BODY = new Uint8Array(0);

/**
 * A content type a codec names, as the dotted form of an object identifier.
 */
const CONTENT_TYPE = "1.2.840.113549.1.7.1";

/**
 * A resync that the server answers at once.
 */
const ANSWERED_RESYNC = (): Promise<void> => Promise.resolve();

/**
 * What an entry hands the application, in the order it does: the stamp of
 * each delivered update, each resync it asks of the server, and each gap it
 * hands to the gap observer.
 */
type Event = bigint | "resync" | readonly ["gap", bigint, bigint];

/**
 * The subscribe options of an entry whose deliveries land in `events`.
 */
function recording(events: Event[]): SubscribeOptions<Uint8Array> {
	const options = {
		codec: engine.opaque,
		onUpdate: (_message: Uint8Array, update: Frame): void => {
			events.push(update.order);
		},
	};
	return options;
}

/**
 * The subscribe options of an entry whose deliveries and gaps land in
 * `events`.
 */
function observing(events: Event[]): SubscribeOptions<Uint8Array> {
	const options = {
		...recording(events),
		onGap: (_topic: string, expected: bigint, received: bigint): void => {
			events.push(["gap", expected, received]);
		},
	};
	return options;
}

/**
 * A resync whose asks land in `events`.
 */
function resyncInto(events: Event[]): () => Promise<void> {
	return (): Promise<void> => {
		events.push("resync");
		return Promise.resolve();
	};
}

/**
 * The entry of {@link PRICES} that `entries` opens under `options`.
 */
function openPrices(
	entries: Entries,
	options: SubscribeOptions<Uint8Array>,
): Entry {
	const delivery = Delivery.of(PRICES, options, engine);
	const entry = entries.open(PRICES, delivery, options);
	return entry;
}

/**
 * A live entry of {@link PRICES}: its `sub/` left, and the server
 * acknowledged it.
 */
function livePrices(
	entries: Entries,
	options: SubscribeOptions<Uint8Array>,
): Entry {
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
 * The profile opaque codec under the content type `contentOid`.
 */
function codecNaming(contentOid: OidName): MessageCodec<Uint8Array> {
	const codec = {
		contentOid,
		encode: (message: Uint8Array): Uint8Array =>
			engine.opaque.encode(message),
		decode: (bodyDer: Uint8Array): Uint8Array =>
			engine.opaque.decode(bodyDer),
	};
	return codec;
}

/**
 * An earlier entry of {@link PRICES} that ended one way, so a newer entry
 * holds the topic.
 */
interface EarlierEnding {
	readonly ending: string;
	readonly end: (entries: Entries, earlier: Entry) => void;
}

/**
 * Every way an earlier entry ends while a newer one may follow it.
 */
const EARLIER_ENDINGS: readonly EarlierEnding[] = [
	{
		ending: "unsubscribed",
		end: (entries, earlier) => {
			entries.end(earlier, "unsubscribed");
		},
	},
	{
		ending: "completed",
		end: (entries) => {
			entries.complete(PRICES);
		},
	},
	{
		ending: "refused on replay",
		end: (_entries, earlier) => {
			earlier.lapse();
			earlier.leaving();
			earlier.refused();
		},
	},
];

describe("PayloadShape", () => {
	it("a decoding shape decodes an update after the caller frees its codec contentOid", async () => {
		const contentOid = engine.oid(CONTENT_TYPE);
		const source = { codec: codecNaming(contentOid) };
		const shape = PayloadShape.of(source, engine, "decoding");

		contentOid.free();

		const pushed = await update(1);
		expect(shape.decode(pushed)).toEqual(EMPTY_BODY);
	});
});

describe("Entry gaps", () => {
	it("resyncs before it delivers the revealing update", async () => {
		const events: Event[] = [];
		const entry = livePrices(new Entries(), recording(events));
		const resync = resyncInto(events);

		await entry.receive(await update(1), resync);
		await entry.receive(await update(3), resync);

		expect(events).toEqual([1n, "resync", 3n]);
	});

	it("delivers a replayed order below the revealing update in order", async () => {
		const events: Event[] = [];
		const entry = livePrices(new Entries(), recording(events));
		const resyncing = held();
		await entry.receive(await update(1), ANSWERED_RESYNC);

		const third = await update(3);
		const awaitingResync = (): Promise<void> => resyncing.answer;
		const revealing = entry.receive(third, awaitingResync);

		await entry.receive(await update(2), ANSWERED_RESYNC);
		resyncing.settle();
		await revealing;

		expect(events).toEqual([1n, 2n, 3n]);
	});

	it("hands a gap to its observer in place of the resync", async () => {
		const events: Event[] = [];
		const entry = livePrices(new Entries(), observing(events));
		const resync = resyncInto(events);

		await entry.receive(await update(1), resync);
		await entry.receive(await update(3), resync);

		expect(events).toEqual([1n, ["gap", 2n, 3n], 3n]);
	});

	it("a lapsed entry re-baselines, so its replay delivers the first stamp again", async () => {
		const events: Event[] = [];
		const entry = livePrices(new Entries(), recording(events));
		await entry.receive(await update(1), ANSWERED_RESYNC);

		const lapsed = entry.lapse();
		entry.leaving();
		entry.acknowledged();

		await entry.receive(await update(1), ANSWERED_RESYNC);

		expect(lapsed).toBe(true);
		expect(events).toEqual([1n, 1n]);
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

	it("a refused resync leaves a live entry live", () => {
		const entry = livePrices(new Entries(), recording([]));
		entry.leaving();
		entry.refused();
		expect(entry.state).toBe("live");
	});

	it("an ended entry wants no later sub/", () => {
		const entries = new Entries();
		const entry = livePrices(entries, recording([]));
		entries.end(entry, "unsubscribed");
		expect(entry.wants()).toBe(false);
	});

	it.each(EARLIER_ENDINGS)(
		"the release of an earlier entry $ending leaves a newer entry live",
		({ end }) => {
			const entries = new Entries();
			const earlier = livePrices(entries, recording([]));
			end(entries, earlier);
			const newer = livePrices(entries, recording([]));

			const released = entries.end(earlier, "unsubscribed");

			expect(released).toBe(false);
			expect(newer.state).toBe("live");
		},
	);

	it("a completion ends the entry and tells its end observer", () => {
		const ended: string[] = [];
		const options = {
			...recording([]),
			onEnd: (topic: string): void => {
				ended.push(topic);
			},
		};

		const entries = new Entries();
		const entry = livePrices(entries, options);
		const completed = entries.complete(PRICES);
		expect(completed).toBe(true);
		expect(entry.state).toBe("ended");
		expect(ended).toEqual(["prices"]);
	});
});

describe("SubscriptionManager ports", () => {
	it("the manager cannot emit outside the lane", () => {
		const managed = expectTypeOf<keyof SubscriptionManager>();
		expectTypeOf<keyof ClientPorts>().toEqualTypeOf<PortsMembers>();
		expectTypeOf<keyof ServePort>().toEqualTypeOf<ServeMembers>();
		expectTypeOf<keyof CommandLane>().toEqualTypeOf<LaneMembers>();
		managed.toEqualTypeOf<ManagerMembers>();
	});

	it("the manager and reattach take ports, not a client", () => {
		const constructed = expectTypeOf(SubscriptionManager);
		const reattached = expectTypeOf<Reattach>();
		constructed.constructorParameters.toEqualTypeOf<ManagerArguments>();
		reattached.parameters.toEqualTypeOf<[ClientPorts]>();
		expectTypeOf<TightbeamWsClient>().not.toExtend<ClientPorts>();
	});
});
