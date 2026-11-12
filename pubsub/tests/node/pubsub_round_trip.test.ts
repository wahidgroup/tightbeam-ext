import { describe, expect, expectTypeOf, it } from "vitest";

import { Engine } from "@wahidgroup/tightbeam-ws-client";
import type { BodyDecryptor, TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";
import type { Gap, HandlerSubscription, IteratingSubscription, Update } from "@wahidgroup/tightbeam-pubsub-client";
import { ClientPorts, MAX_DEFERRED, SubscriptionManager, Topic } from "@wahidgroup/tightbeam-pubsub-client";

import { CONTENT_TYPE, codecNaming } from "#pubsub-codecs";
import WIRE from "#pubsub-wire" with { type: "json" };
import { Identities } from "#ws-env";
import { TopicRun } from "../fixtures.js";
import { STACK } from "./stack.js";

const ENCODER = new TextEncoder();

const DECODER = new TextDecoder();

const ENGINE = await Engine.load();

/**
 * The publisher's frame-level signing key for the frame-in-frame tests.
 */
const SIGNING_KEY = ENGINE.signingKey(new Uint8Array(32).fill(1));

/**
 * The signature halves of the publisher, which build and verify each signed
 * inner frame.
 */
const SIGNATURE = {
	signer: SIGNING_KEY,
	verifier: SIGNING_KEY.verifyingKey(),
};

/**
 * The topics of this run.
 */
const TOPICS = TopicRun.current;

function connect(): Promise<TightbeamWsClient> {
	return ENGINE.connectMutual(STACK.pubsubEndpoint, Identities.stack.demo(), STACK.dial.paywall.sessionOptions());
}

/**
 * A client of the demo server that relays every publish through the
 * processor servlet.
 */
function connectProcessed(): Promise<TightbeamWsClient> {
	return ENGINE.connectMutual(
		STACK.pubsubProcessedEndpoint,
		Identities.stack.demo(),
		STACK.dial.paywall.sessionOptions(),
	);
}

/**
 * A manager over the ports of `client`.
 */
function managerOver(client: TightbeamWsClient): SubscriptionManager {
	const ports = ClientPorts.split(client);
	const manager = new SubscriptionManager(ports);
	return manager;
}

/**
 * Publish the `payload` of `post` on its `topic` with a `pub/` command.
 */
async function publish(
	manager: SubscriptionManager,
	post: { readonly topic: string; readonly payload: string },
): Promise<void> {
	await manager.publish(post.topic, ENCODER.encode(post.payload), {
		codec: ENGINE.opaque,
	});
}

/**
 * One received update, reduced to what the assertions care about.
 */
interface Received {
	readonly payload: string;
	readonly order: bigint;
}

function received(update: Update<Uint8Array>): Received {
	return {
		payload: DECODER.decode(update.message),
		order: update.frame.order,
	};
}

/**
 * The next iterated update, within a deadline so a regression fails
 * instead of hanging.
 */
async function nextUpdate<T>(updates: AsyncIterator<Update<T>>): Promise<Update<T>> {
	let timer: NodeJS.Timeout | undefined;
	const deadline = new Promise<never>((_resolve, reject) => {
		timer = setTimeout(() => {
			reject(new Error("timed out waiting for an update"));
		}, 10_000);
	});

	try {
		const result = await Promise.race([updates.next(), deadline]);
		if (result.done === true) {
			throw new Error("the subscription completed before the update");
		}

		return result.value;
	} finally {
		clearTimeout(timer);
	}
}

/**
 * The next iterated update, reduced to what the assertions care about.
 */
async function nextReceived(updates: AsyncIterator<Update<Uint8Array>>): Promise<Received> {
	const update = await nextUpdate(updates);
	return received(update);
}

/**
 * An update handler that rejects the `poison` payload and records
 * every other delivery.
 */
function poisonedHandler(poison: string, delivered: string[]): (message: Uint8Array) => void {
	return (message: Uint8Array): void => {
		const payload = DECODER.decode(message);
		if (payload === poison) {
			throw new Error("poisoned update");
		}

		delivered.push(payload);
	};
}

/**
 * Subscribe `manager` to `topic` in iterator mode.
 */
async function subscribed(manager: SubscriptionManager, topic: string): Promise<IteratingSubscription<Uint8Array>> {
	const subscription = await manager.subscribe(topic, {
		codec: ENGINE.opaque,
	});
	return subscription;
}

/**
 * The decoding shape of every iterating subscription the manager tests make.
 */
const OPAQUE = { codec: ENGINE.opaque };

/**
 * The options of every handler subscription that ignores its updates.
 */
const HANDLED = {
	codec: ENGINE.opaque,
	onUpdate: (): undefined => undefined,
};

/**
 * The body of every publish whose payload no test reads.
 */
const HELD_BODY = ENCODER.encode("held");

/**
 * A payload one octet past the initial stream credit of a peer, 64 chunks of
 * 16 KiB, so its publish waits for the grants of the relay.
 */
const PAST_INITIAL_CREDIT = new Uint8Array(1024 * 1024 + 1).fill(0x61);

/**
 * A payload that fits one chunk.
 */
const SMALL_BODY = ENCODER.encode("small");

/**
 * The refusal of a call on a disposed manager.
 */
const DISPOSED = expect.objectContaining({ code: "Disposed" });

/**
 * Publish orders 2 through one past the queue bound of the demo server on
 * `topic`, so while update 1 stays in flight the burst fills the queue of the
 * subscriber and evicts update 2.
 */
async function overfill(manager: SubscriptionManager, topic: string): Promise<void> {
	const last = STACK.pubsubQueueCapacity + 2;
	for (let order = 2; order <= last; order += 1) {
		await publish(manager, { topic, payload: String(order) });
	}
}

/**
 * A latch the test opens by hand.
 */
interface Latch {
	readonly opened: Promise<void>;
	readonly open: () => void;
}

/**
 * A latch that stays shut until the test opens it.
 */
function latch(): Latch {
	let open = (): void => undefined;
	const opened = new Promise<void>((resolve) => {
		open = (): void => {
			resolve();
		};
	});

	return { opened, open };
}

/**
 * Publish `count` commands on `topic` through `manager`, whose connection is
 * lost, so the lane of the topic defers each one.
 */
async function deferEvery(manager: SubscriptionManager, topic: string, count: number): Promise<void> {
	for (let deferred = 0; deferred < count; deferred += 1) {
		await manager.publish(topic, HELD_BODY, OPAQUE);
	}
}

/**
 * A call that a disposed manager refuses, run on `manager` over `client`.
 */
interface DisposedCall {
	readonly call: string;
	readonly run: (manager: SubscriptionManager, client: TightbeamWsClient) => Promise<unknown>;
}

/**
 * Every call that a disposed manager refuses.
 */
const DISPOSED_CALLS: readonly DisposedCall[] = [
	{
		call: "subscribe",
		run: (manager) => manager.subscribe(TOPICS.topic("disposed"), OPAQUE),
	},
	{
		call: "publish",
		run: (manager) => manager.publish(TOPICS.topic("disposed"), HELD_BODY, OPAQUE),
	},
	{
		call: "reattach",
		run: (manager, client) => manager.reattach(ClientPorts.split(client)),
	},
];

describe("pub/sub round-trips against the dockerized demo server", () => {
	it("delivers published updates in dense order", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("prices");
		const subscription = await subscribed(manager, topic);
		const updates = subscription[Symbol.asyncIterator]();

		for (const payload of ["one", "two", "three"]) {
			await publish(manager, { topic, payload });
		}

		const delivered = [await nextReceived(updates), await nextReceived(updates), await nextReceived(updates)];
		expect(delivered).toEqual([
			{ payload: "one", order: 1n },
			{ payload: "two", order: 2n },
			{ payload: "three", order: 3n },
		]);
	});

	it("reveals a failed delivery as a gap on the next update", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("poisoned");
		const delivered: string[] = [];
		const gaps: Gap[] = [];

		await manager.subscribe(topic, {
			codec: ENGINE.opaque,
			onUpdate: poisonedHandler("two", delivered),
			onGap: (_topic, gap) => {
				gaps.push(gap);
			},
		});

		for (const payload of ["one", "two", "three"]) {
			await publish(manager, { topic, payload });
		}

		await expect.poll(() => gaps, { timeout: 10_000 }).toEqual([{ expected: 2n, received: 3n }]);
		await expect.poll(() => delivered, { timeout: 10_000 }).toEqual(["one", "three"]);
	});

	it("reveals a first-delivery failure as a gap on the next update", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("poisoned-first");
		const delivered: string[] = [];
		const gaps: Gap[] = [];

		/*
		 * The very first update fails, so no baseline exists when
		 * the second arrives: the witnessed stamp is the only trace
		 * of the loss.
		 */
		await manager.subscribe(topic, {
			codec: ENGINE.opaque,
			onUpdate: poisonedHandler("one", delivered),
			onGap: (_topic, gap) => {
				gaps.push(gap);
			},
		});

		for (const payload of ["one", "two"]) {
			await publish(manager, { topic, payload });
		}

		await expect.poll(() => gaps, { timeout: 10_000 }).toEqual([{ expected: 1n, received: 2n }]);
		await expect.poll(() => delivered, { timeout: 10_000 }).toEqual(["two"]);
	});

	it("still delivers the gap-revealing update when onGap throws", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("gap-throw");
		const delivered: string[] = [];

		await manager.subscribe(topic, {
			codec: ENGINE.opaque,
			onUpdate: poisonedHandler("two", delivered),
			onGap: () => {
				throw new Error("gap observer failure");
			},
		});

		for (const payload of ["one", "two", "three"]) {
			await publish(manager, { topic, payload });
		}

		await expect.poll(() => delivered, { timeout: 10_000 }).toEqual(["one", "three"]);
	});

	it("acknowledged subscriptions report a live state", async () => {
		await using client = await connect();
		const manager = managerOver(client);

		const subscription = await subscribed(manager, TOPICS.topic("state"));
		expect(subscription.state).toBe("live");

		await subscription.unsubscribe();
		expect(subscription.state).toBe("ended");
	});

	it("claims stream dispatch exclusively for the manager", async () => {
		await using client = await connect();
		void managerOver(client);
		const claimed = expect.objectContaining({
			code: "ServeDispatchClaimed",
		});

		expect(() => {
			client.serve(() => undefined);
		}).toThrow(claimed);
		expect(() => {
			client.serveStreaming(() => undefined);
		}).toThrow(claimed);
	});

	it("refuses a manager over a client that already serves a shared handler", async () => {
		await using client = await connect();
		client.serve(() => undefined);
		const shared = expect.objectContaining({
			code: "ServeDispatchShared",
		});

		expect(() => managerOver(client)).toThrow(shared);
	});

	it("fans one publish out to every subscriber", async () => {
		await using first = await connect();
		await using second = await connect();
		const topic = TOPICS.topic("fanout");
		const firstManager = managerOver(first);
		const firstUpdates = (await subscribed(firstManager, topic))[Symbol.asyncIterator]();
		const secondUpdates = (await subscribed(managerOver(second), topic))[Symbol.asyncIterator]();

		await publish(firstManager, { topic, payload: "tick" });

		expect(await nextReceived(firstUpdates)).toEqual({
			payload: "tick",
			order: 1n,
		});
		expect(await nextReceived(secondUpdates)).toEqual({
			payload: "tick",
			order: 1n,
		});
	});

	it("stops delivery after unsubscribe", async () => {
		await using leaver = await connect();
		await using stayer = await connect();
		const topic = TOPICS.topic("churn");
		const leaverManager = managerOver(leaver);
		const leaverSubscription = await subscribed(leaverManager, topic);
		const leaverUpdates = leaverSubscription[Symbol.asyncIterator]();
		const stayerUpdates = (await subscribed(managerOver(stayer), topic))[Symbol.asyncIterator]();

		await publish(leaverManager, { topic, payload: "before" });
		expect(await nextReceived(leaverUpdates)).toEqual({
			payload: "before",
			order: 1n,
		});

		await leaverSubscription.unsubscribe();
		await publish(leaverManager, { topic, payload: "after" });

		/*
		 * The staying subscriber receiving the second update is the
		 * synchronization point: fan-out already ran, and the leaver
		 * was not part of it.
		 */
		expect(await nextReceived(stayerUpdates)).toEqual({
			payload: "before",
			order: 1n,
		});
		expect(await nextReceived(stayerUpdates)).toEqual({
			payload: "after",
			order: 2n,
		});
		expect((await leaverUpdates.next()).done).toBe(true);
	});

	it("drops an update already in flight when unsubscribe lands", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("in-flight");
		const delivered: string[] = [];
		const decrypting = latch();
		const parked = latch();

		/*
		 * A BYO decryptor that parks until released: the controllable
		 * async window an envelope layer opens inside a delivery, so
		 * unsubscribe can land while the update is in flight.
		 */
		const key = ENGINE.aes256Gcm(STACK.topicSecret.shared);
		const stalled: BodyDecryptor = {
			decrypt: async (sealed) => {
				decrypting.open();
				await parked.opened;
				return key.decrypt(sealed);
			},
		};

		const subscription = await manager.subscribe(topic, {
			envelope: ENGINE.envelope(ENGINE.opaque).sealed({
				opener: stalled,
			}),
			onUpdate: (message) => {
				delivered.push(DECODER.decode(message));
			},
		});
		await manager.publish(topic, ENCODER.encode("late"), {
			envelope: ENGINE.envelope(ENGINE.opaque).sealed({
				sealer: key,
			}),
		});

		await decrypting.opened;
		await manager.unsubscribe(topic);
		parked.open();
		await subscription.settled();

		expect(delivered).toEqual([]);
	});

	it("routes each update of a topic led by a byte order mark to that topic alone", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const plain = TOPICS.topic("marked");
		const marked = `\uFEFF${plain}`;
		const plainUpdates = (await subscribed(manager, plain))[Symbol.asyncIterator]();
		const markedUpdates = (await subscribed(manager, marked))[Symbol.asyncIterator]();

		await publish(manager, { topic: marked, payload: "marked" });
		await publish(manager, { topic: plain, payload: "plain" });

		expect(await nextReceived(markedUpdates)).toEqual({
			payload: "marked",
			order: 1n,
		});
		expect(await nextReceived(plainUpdates)).toEqual({
			payload: "plain",
			order: 1n,
		});
	});

	it("rejects a forbidden topic with PermissionDenied", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const denied = manager.subscribe(TOPICS.forbidden("keys"), {
			codec: ENGINE.opaque,
			onUpdate: () => {
				throw new Error("a denied topic must not deliver");
			},
		});

		await expect(denied).rejects.toMatchObject({
			code: "PermissionDenied",
		});
		expect(manager.topics).toEqual([]);
	});

	it("holds topic names to the same octet limit as the server", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const longest = TOPICS.topic("limit/").padEnd(WIRE.topicMaxLen, "a");
		const overlong = `${longest}a`;
		const body = new Uint8Array(0);
		const bypassingId = `${WIRE.prefixes.subscribe}${overlong}`;
		const command = ENGINE.frameBuilder(body).withId(bypassingId);

		const bypassing = await command.build();
		const accepted = await subscribed(manager, longest);
		const refused = client.emit(bypassing);
		const tooLong = expect.objectContaining({ code: "TooLong" });

		expect(accepted.state).toBe("live");
		await expect(refused).rejects.toMatchObject({
			code: "InvalidArgument",
		});
		expect(() => Topic.parse(overlong)).toThrow(tooLong);

		await accepted.unsubscribe();
	});

	it("replays subscriptions onto a replacement connection", async () => {
		const first = await connect();
		const manager = managerOver(first);
		const topic = TOPICS.topic("reattach");
		const subscription = await subscribed(manager, topic);
		const updates = subscription[Symbol.asyncIterator]();

		try {
			await publish(manager, { topic, payload: "before" });
			expect(await nextReceived(updates)).toEqual({
				payload: "before",
				order: 1n,
			});
		} finally {
			await first.close();
		}

		const second = await connect();
		try {
			await manager.reattach(ClientPorts.split(second));
			expect(subscription.state).toBe("live");

			await publish(manager, { topic, payload: "after" });
			expect(await nextReceived(updates)).toEqual({
				payload: "after",
				order: 2n,
			});
		} finally {
			await second.close();
		}
	});

	it("reports a delivery gap through onGap after a DropOldest eviction", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("burst");
		const orders: bigint[] = [];
		const gaps: [string, bigint, bigint][] = [];

		/*
		 * Every update handler parks on this latch, so the first
		 * update stays unacknowledged while the burst overfills the
		 * server's delivery queue.
		 */
		const released = latch();

		await manager.subscribe(topic, {
			codec: ENGINE.opaque,
			onUpdate: async (_payload, update) => {
				orders.push(update.order);
				await released.opened;
			},
			onGap: (gapTopic, gap) => {
				gaps.push([gapTopic.name, gap.expected, gap.received]);
			},
		});

		await publish(manager, { topic, payload: "1" });
		await expect.poll(() => orders).toEqual([1n]);
		await overfill(manager, topic);

		released.open();
		await expect.poll(() => gaps).toEqual([[topic, 2n, 3n]]);
		/*
		 * The eviction dropped update 2: order 3 follows order 1.
		 */
		await expect.poll(() => orders.slice(0, 2)).toEqual([1n, 3n]);
	});

	it("delivers the revealing update of a gap that no observer answers", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("unobserved-gap");
		const orders: bigint[] = [];
		const released = latch();

		const subscription = await manager.subscribe(topic, {
			codec: ENGINE.opaque,
			onUpdate: async (_payload, update) => {
				orders.push(update.order);
				await released.opened;
			},
		});

		await publish(manager, { topic, payload: "1" });
		await expect.poll(() => orders).toEqual([1n]);
		await overfill(manager, topic);

		released.open();
		await expect.poll(() => orders.slice(0, 2)).toEqual([1n, 3n]);
		expect(subscription.state).toBe("live");
	});

	it("relays a signed inner frame with its metadata end to end", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("orders");
		const subscription = await manager.subscribe(topic, {
			codec: ENGINE.framed,
		});

		const updates = subscription[Symbol.asyncIterator]();

		const fill = ENCODER.encode("fill 42 @ 101.5");
		const inner = await ENGINE.frameBuilder(fill)
			.withId("order-42")
			.withOrder(7)
			.withPriority(ENGINE.MessagePriority.Expedited)
			.withLifetime(60)
			.withSigner(SIGNING_KEY)
			.build();
		await manager.publish(topic, inner, { codec: ENGINE.framed });

		/*
		 * The wrapper carries the registry's stamps.
		 */
		const update = await nextUpdate(updates);
		expect(DECODER.decode(update.frame.id)).toBe(topic);
		expect(update.frame.order).toBe(1n);

		/*
		 * The inner frame is the application's, byte-for-byte.
		 */
		const relayed = update.message;
		expect(relayed.toDer()).toEqual(inner.toDer());
		await expect(relayed.verify(SIGNING_KEY.verifyingKey())).resolves.toBeUndefined();
		expect(DECODER.decode(relayed.id)).toBe("order-42");
		expect(relayed.order).toBe(7n);
		expect(relayed.priority).toBe(ENGINE.MessagePriority.Expedited);
		expect(relayed.lifetime).toBe(60n);
		await expect(relayed.open(ENGINE.opaque)).resolves.toEqual(fill);
	});

	it("relays a sealed inner frame the broker cannot read", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("sealed");

		/*
		 * One declaration serves both directions: publish builds a
		 * signed, sealed inner frame, and every unwrapped update is
		 * PROVEN to carry the publisher's signature and the topic
		 * seal. A cleartext or unsigned frame rejects instead.
		 */
		const cipher = ENGINE.aes256Gcm(STACK.topicSecret.shared);
		const secrets = ENGINE.envelope(ENGINE.opaque).signed(SIGNATURE).sealed({ sealer: cipher, opener: cipher });

		const subscription = await manager.subscribe(topic, {
			envelope: secrets,
		});

		const updates = subscription[Symbol.asyncIterator]();
		const secret = ENCODER.encode("for subscribers only");
		await manager.publish(topic, secret, { envelope: secrets });

		const update = await nextUpdate(updates);
		expect(update.message).toEqual(secret);
		expect(DECODER.decode(update.frame.id)).toBe(topic);
		expect(update.frame.order).toBe(1n);
	});

	it("routes non-topic server streams to the fallback", async () => {
		await using client = await connect();
		const notices: string[] = [];
		const ports = ClientPorts.split(client);
		const manager = new SubscriptionManager(ports, {
			fallback: (update) => {
				notices.push(DECODER.decode(update.id));
				return undefined;
			},
		});

		const empty = new Uint8Array(0);
		const poke = await ENGINE.frameBuilder(empty).withId("poke").build();

		await client.emit(poke);

		await expect.poll(() => notices).toEqual(["notice"]);
		expect(manager.topics).toEqual([]);
	});
});

describe("pub/sub against the dockerized processed demo server", () => {
	it("rejects a publish that the processor servlet refuses", async () => {
		await using client = await connectProcessed();
		const manager = managerOver(client);
		const topic = TOPICS.topic("unprocessable");

		const refused = publish(manager, { topic, payload: "no inner frame" });

		await expect(refused).rejects.toMatchObject({
			code: "Unavailable",
		});
	});
});

describe("SubscriptionManager commands against the dockerized demo server", () => {
	it("two publishes on one topic, the first past the initial stream credit, reach a subscriber in send order", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("credit-order");
		const subscription = await subscribed(manager, topic);
		const updates = subscription[Symbol.asyncIterator]();

		const first = manager.publish(topic, PAST_INITIAL_CREDIT, OPAQUE);
		const second = manager.publish(topic, SMALL_BODY, OPAQUE);
		await Promise.all([first, second]);

		const large = await nextUpdate(updates);
		const small = await nextUpdate(updates);
		expect(large.message).toEqual(PAST_INITIAL_CREDIT);
		expect(small.message).toEqual(SMALL_BODY);
	});

	it("a subscribe made while the unsub/ of its topic is in flight delivers no update of the subscription it replaced", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("resubscribe");
		const replaced = await manager.subscribe(topic, HANDLED);

		const publishing = publish(manager, { topic, payload: "replaced" });
		const leaving = replaced.unsubscribe();
		const current = await subscribed(manager, topic);
		await Promise.all([publishing, leaving]);
		await publish(manager, { topic, payload: "current" });

		const updates = current[Symbol.asyncIterator]();
		expect(await nextReceived(updates)).toEqual({
			payload: "current",
			order: 2n,
		});
	});

	it("leaves a newer subscription live when an old handle unsubscribes again", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("newer");
		const old = await subscribed(manager, topic);
		await old.unsubscribe();
		const current = await subscribed(manager, topic);
		const updates = current[Symbol.asyncIterator]();

		await old.unsubscribe();
		await publish(manager, { topic, payload: "kept" });

		expect(current.state).toBe("live");
		expect(await nextReceived(updates)).toEqual({
			payload: "kept",
			order: 1n,
		});
	});

	it("a break out of a subscription unsubscribes it", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const subscription = await subscribed(manager, TOPICS.topic("break"));
		const updates = subscription[Symbol.asyncIterator]();

		await updates.return?.();

		expect(subscription.state).toBe("ended");
		expect(manager.topics).toEqual([]);
	});

	it("a handler subscription has no iterator", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("handler");

		const subscription = await manager.subscribe(topic, HANDLED);
		expectTypeOf(subscription).toEqualTypeOf<HandlerSubscription>();
		expectTypeOf(subscription).not.toHaveProperty(Symbol.asyncIterator);
		expect(Symbol.asyncIterator in subscription).toBe(false);
	});

	it("refuses a second iterator as AlreadyIterating", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("iterated");
		const subscription = await subscribed(manager, topic);
		subscription[Symbol.asyncIterator]();

		const refusal = expect.objectContaining({
			code: "AlreadyIterating",
		});
		expect(() => subscription[Symbol.asyncIterator]()).toThrow(refusal);
	});

	it("refuses a second subscribe to a live topic as AlreadySubscribed", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("twice");
		await subscribed(manager, topic);

		const second = manager.subscribe(topic, OPAQUE);
		await expect(second).rejects.toMatchObject({
			code: "AlreadySubscribed",
		});
	});

	it("refuses to unsubscribe from an invalid topic name", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const left = manager.unsubscribe("");
		await expect(left).rejects.toMatchObject({ code: "Empty" });
	});
});

describe("SubscriptionManager reattach against the dockerized demo server", () => {
	it("the lanes of one manager defer at most MAX_DEFERRED commands across their topics", async () => {
		const client = await connect();
		const manager = managerOver(client);
		await client.close();
		const share = MAX_DEFERRED / 2;

		await deferEvery(manager, TOPICS.topic("budget-first"), share);
		await deferEvery(manager, TOPICS.topic("budget-second"), share);

		const third = TOPICS.topic("budget-third");
		const refused = manager.publish(third, HELD_BODY, OPAQUE);

		await expect(refused).rejects.toMatchObject({ code: "DeferralFull" });
		await manager[Symbol.asyncDispose]();
	});

	it("defers a subscribe on a lost connection, and the reattach makes it live", async () => {
		const first = await connect();
		const manager = managerOver(first);

		await first.close();

		const topic = TOPICS.topic("deferred-subscribe");
		const subscription = await subscribed(manager, topic);
		const deferred = subscription.state;
		const updates = subscription[Symbol.asyncIterator]();

		const second = await connect();
		try {
			await manager.reattach(ClientPorts.split(second));
			await publish(manager, { topic, payload: "replayed" });

			expect(deferred).toBe("deferred");
			expect(subscription.state).toBe("live");
			expect(await nextReceived(updates)).toEqual({
				payload: "replayed",
				order: 1n,
			});
		} finally {
			await second.close();
		}
	});

	it("replays the sub/ of a live subscription before the publish its lost connection deferred", async () => {
		const first = await connect();
		const manager = managerOver(first);
		const topic = TOPICS.topic("deferred-publish");
		const subscription = await subscribed(manager, topic);
		const updates = subscription[Symbol.asyncIterator]();
		await first.close();
		await publish(manager, { topic, payload: "deferred" });

		const second = await connect();
		try {
			await manager.reattach(ClientPorts.split(second));

			expect(await nextReceived(updates)).toEqual({
				payload: "deferred",
				order: 1n,
			});
			expect(subscription.state).toBe("live");
		} finally {
			await second.close();
		}
	});

	it("replays a deferred unsubscribe before a subscribe made after the reattach", async () => {
		const first = await connect();
		const manager = managerOver(first);
		const topic = TOPICS.topic("deferred-unsubscribe");
		await subscribed(manager, topic);
		await first.close();
		await manager.unsubscribe(topic);

		const second = await connect();
		try {
			const replayed = manager.reattach(ClientPorts.split(second));
			const returning = manager.subscribe(topic, OPAQUE);

			await replayed;

			const current = await returning;
			const updates = current[Symbol.asyncIterator]();

			await publish(manager, { topic, payload: "fresh" });

			expect(await nextReceived(updates)).toEqual({
				payload: "fresh",
				order: 1n,
			});
		} finally {
			await second.close();
		}
	});

	it("a reattach that the new client refuses leaves the manager on its ports", async () => {
		await using first = await connect();
		const manager = managerOver(first);
		const second = await connect();
		second.serve(() => undefined);

		const reattached = manager.reattach(ClientPorts.split(second));
		await expect(reattached).rejects.toMatchObject({ code: "ServeDispatchShared" });
		await second.close();

		const topic = TOPICS.topic("refused-reattach");
		const subscription = await subscribed(manager, topic);
		const updates = subscription[Symbol.asyncIterator]();
		await publish(manager, { topic, payload: "kept" });

		expect(subscription.state).toBe("live");
		expect(await nextReceived(updates)).toEqual({
			payload: "kept",
			order: 1n,
		});
	});
});

describe("SubscriptionManager disposal against the dockerized demo server", () => {
	it("a disposed manager detaches its serve handler", async () => {
		await using client = await connect();
		const notices: string[] = [];
		const ports = ClientPorts.split(client);
		const manager = new SubscriptionManager(ports, {
			fallback: (update) => {
				notices.push(DECODER.decode(update.id));
				return undefined;
			},
		});

		const empty = new Uint8Array(0);
		const poke = await ENGINE.frameBuilder(empty).withId("poke").build();

		await manager[Symbol.asyncDispose]();

		const poked = client.emit(poke);
		await expect(poked).rejects.toMatchObject({ code: "Unavailable" });
		expect(notices).toEqual([]);
	});

	it("a disposed manager ends every subscription", async () => {
		await using client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("disposed-end");
		const subscription = await manager.subscribe(topic, HANDLED);

		await manager[Symbol.asyncDispose]();

		expect(subscription.state).toBe("ended");
		expect(manager.topics).toEqual([]);
	});

	it.each(DISPOSED_CALLS)("a disposed manager refuses $call as Disposed", async ({ run }) => {
		await using client = await connect();
		const manager = managerOver(client);
		await manager[Symbol.asyncDispose]();

		const refused = run(manager, client);

		await expect(refused).rejects.toThrow(DISPOSED);
	});

	it("a disposed manager installs no handler on reattach", async () => {
		await using first = await connect();
		await using second = await connect();
		const manager = managerOver(first);
		await manager[Symbol.asyncDispose]();

		const reattached = manager.reattach(ClientPorts.split(second));
		await expect(reattached).rejects.toThrow(DISPOSED);
		expect(() => {
			second.serve(() => undefined);
		}).not.toThrow();
	});
});

describe("SubscriptionManager payload handles against the dockerized demo server", () => {
	it("a deferred publish replays after its caller frees the content type its codec names", async () => {
		const topic = TOPICS.topic("deferred-codec");

		await using watcher = await connect();
		const watching = await subscribed(managerOver(watcher), topic);
		const updates = watching[Symbol.asyncIterator]();
		const lost = await connect();
		const publisher = managerOver(lost);
		await lost.close();

		/*
		 * The lost connection defers the publish, and the caller frees
		 * its content type before the replay builds the frame.
		 */
		const contentOid = ENGINE.oid(CONTENT_TYPE);
		const payload = { codec: codecNaming(ENGINE, contentOid) };
		await publisher.publish(topic, HELD_BODY, payload);
		contentOid.free();

		await using replacement = await connect();
		await publisher.reattach(ClientPorts.split(replacement));

		expect(await nextReceived(updates)).toEqual({
			payload: "held",
			order: 1n,
		});
	});

	it("a disposal over a publish in flight resolves once the client closes", async () => {
		const client = await connect();
		const manager = managerOver(client);
		const topic = TOPICS.topic("dispose-close");
		const publishing = manager.publish(topic, PAST_INITIAL_CREDIT, OPAQUE);

		const disposing = manager[Symbol.asyncDispose]();
		await client.close();

		await expect(disposing).resolves.toBeUndefined();
		await expect(publishing).resolves.toBeUndefined();
	});
});
