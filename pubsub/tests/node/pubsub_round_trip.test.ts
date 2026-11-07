import { describe, expect, expectTypeOf, it } from "vitest";

import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";
import type {
	BodyDecryptor,
	MessageCodec,
	Oid,
	OidName,
} from "@wahidgroup/tightbeam-ws-client";
import type {
	HandlerSubscription,
	IteratingSubscription,
	Update,
} from "@wahidgroup/tightbeam-pubsub-client";
import {
	ClientPorts,
	MAX_DEFERRED,
	SubscriptionManager,
	Topic,
} from "@wahidgroup/tightbeam-pubsub-client";

import WIRE from "#pubsub-wire" with { type: "json" };
import { demoIdentity } from "#ws-env";
import { mutualSessionOptions, withClient } from "#ws-fixtures";
import { STACK } from "./stack.js";

const ENCODER = new TextEncoder();

const DECODER = new TextDecoder();

const ENGINE = await TightbeamWsClient.init();

/**
 * The publisher's frame-level signing key for the frame-in-frame tests.
 */
const SIGNING_KEY = ENGINE.signingKey(new Uint8Array(32).fill(1));

/**
 * The demo server's registry is shared by every connection of the whole
 * suite run, so each test isolates itself on its own topic.
 */
const RUN = Math.random().toString(36).slice(2, 10);

function testTopic(name: string): string {
	return `e2e/${RUN}/${name}`;
}

function connect(): Promise<TightbeamWsClient> {
	return ENGINE.connectMutual(
		STACK.pubsubEndpoint,
		demoIdentity(),
		mutualSessionOptions(STACK.paywall),
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
 * Publish `payload` on `topic` through the wire's `pub/` command.
 */
async function publish(
	manager: SubscriptionManager,
	topic: string,
	payload: string,
): Promise<void> {
	await manager.publish(topic, ENCODER.encode(payload), {
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
async function nextUpdate<T>(
	updates: AsyncIterator<Update<T>>,
): Promise<Update<T>> {
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
async function nextReceived(
	updates: AsyncIterator<Update<Uint8Array>>,
): Promise<Received> {
	const update = await nextUpdate(updates);
	return received(update);
}

/**
 * An update handler that rejects the `poison` payload and records
 * every other delivery.
 */
function poisonedHandler(
	poison: string,
	delivered: string[],
): (message: Uint8Array) => void {
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
async function subscribed(
	manager: SubscriptionManager,
	topic: string,
): Promise<IteratingSubscription<Uint8Array>> {
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
 * A content type a codec names, as the dotted form of an object identifier.
 */
const CONTENT_TYPE = "1.2.840.113549.1.7.1";

/**
 * The content type a caller passes, which answers each `clone()` with a
 * real engine handle and keeps it. It is a user implementation of the public
 * `OidName` port, and it records what crossed the boundary: the handles the
 * manager took.
 */
class KeptName implements OidName {
	readonly copies: Oid[] = [];

	clone(): Oid {
		const copy = ENGINE.oid(CONTENT_TYPE);
		this.copies.push(copy);
		return copy;
	}

	toString(): string {
		return CONTENT_TYPE;
	}
}

/**
 * The profile opaque codec under the content type `contentOid`.
 */
function codecNaming(contentOid: OidName): MessageCodec<Uint8Array> {
	const codec = {
		contentOid,
		encode: (message: Uint8Array): Uint8Array =>
			ENGINE.opaque.encode(message),
		decode: (bodyDer: Uint8Array): Uint8Array =>
			ENGINE.opaque.decode(bodyDer),
	};
	return codec;
}

/**
 * Whether a use of `copy` throws, as a use of a freed glue handle does.
 */
function isFreed(copy: Oid): boolean {
	try {
		copy.toString();
	} catch {
		return true;
	}

	return false;
}

/**
 * Whether `name` handed out a copy, and the manager freed every one.
 */
function allFreed(name: KeptName): boolean {
	const copies = name.copies;
	const freed = copies.length > 0 && copies.every(isFreed);
	return freed;
}

/**
 * Whether `name` handed out a copy, and the manager freed none.
 */
function noneFreed(name: KeptName): boolean {
	const copies = name.copies;
	const kept = copies.length > 0 && !copies.some(isFreed);
	return kept;
}

/**
 * Publish `count` commands on `topic` through `manager`, whose connection is
 * lost, so the lane of the topic defers each one.
 */
async function deferEvery(
	manager: SubscriptionManager,
	topic: string,
	count: number,
): Promise<void> {
	for (let deferred = 0; deferred < count; deferred += 1) {
		await manager.publish(topic, HELD_BODY, OPAQUE);
	}
}

/**
 * A call that a disposed manager refuses, run on `manager` over `client`.
 */
interface DisposedCall {
	readonly call: string;
	readonly run: (
		manager: SubscriptionManager,
		client: TightbeamWsClient,
	) => Promise<unknown>;
}

/**
 * Every call that a disposed manager refuses.
 */
const DISPOSED_CALLS: readonly DisposedCall[] = [
	{
		call: "subscribe",
		run: (manager) => manager.subscribe(testTopic("disposed"), OPAQUE),
	},
	{
		call: "publish",
		run: (manager) =>
			manager.publish(testTopic("disposed"), HELD_BODY, OPAQUE),
	},
	{
		call: "reattach",
		run: (manager, client) => manager.reattach(ClientPorts.split(client)),
	},
];

describe("pub/sub round-trips against the dockerized demo server", () => {
	it("delivers published updates in dense order", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("prices");
			const subscription = await subscribed(manager, topic);
			const updates = subscription[Symbol.asyncIterator]();

			for (const payload of ["one", "two", "three"]) {
				await publish(manager, topic, payload);
			}

			const delivered = [
				await nextReceived(updates),
				await nextReceived(updates),
				await nextReceived(updates),
			];
			expect(delivered).toEqual([
				{ payload: "one", order: 1n },
				{ payload: "two", order: 2n },
				{ payload: "three", order: 3n },
			]);
		});
	});

	it("reveals a failed delivery as a gap on the next update", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("poisoned");
			const delivered: string[] = [];
			const gaps: { expected: bigint; received: bigint }[] = [];

			await manager.subscribe(topic, {
				codec: ENGINE.opaque,
				onUpdate: poisonedHandler("two", delivered),
				onGap: (_topic, expected, received) => {
					gaps.push({ expected, received });
				},
			});

			for (const payload of ["one", "two", "three"]) {
				await publish(manager, topic, payload);
			}

			await expect
				.poll(() => gaps, { timeout: 10_000 })
				.toEqual([{ expected: 2n, received: 3n }]);
			await expect
				.poll(() => delivered, { timeout: 10_000 })
				.toEqual(["one", "three"]);
		});
	});

	it("reveals a first-delivery failure as a gap on the next update", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("poisoned-first");
			const delivered: string[] = [];
			const gaps: { expected: bigint; received: bigint }[] = [];

			/*
			 * The very first update fails, so no baseline exists when
			 * the second arrives: the witnessed stamp is the only trace
			 * of the loss.
			 */
			await manager.subscribe(topic, {
				codec: ENGINE.opaque,
				onUpdate: poisonedHandler("one", delivered),
				onGap: (_topic, expected, received) => {
					gaps.push({ expected, received });
				},
			});

			for (const payload of ["one", "two"]) {
				await publish(manager, topic, payload);
			}

			await expect
				.poll(() => gaps, { timeout: 10_000 })
				.toEqual([{ expected: 1n, received: 2n }]);
			await expect
				.poll(() => delivered, { timeout: 10_000 })
				.toEqual(["two"]);
		});
	});

	it("still delivers the gap-revealing update when onGap throws", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("gap-throw");
			const delivered: string[] = [];

			await manager.subscribe(topic, {
				codec: ENGINE.opaque,
				onUpdate: poisonedHandler("two", delivered),
				onGap: () => {
					throw new Error("gap observer failure");
				},
			});

			for (const payload of ["one", "two", "three"]) {
				await publish(manager, topic, payload);
			}

			await expect
				.poll(() => delivered, { timeout: 10_000 })
				.toEqual(["one", "three"]);
		});
	});

	it("acknowledged subscriptions report a live state", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);

			const subscription = await subscribed(manager, testTopic("state"));
			expect(subscription.state).toBe("live");

			await subscription.unsubscribe();
			expect(subscription.state).toBe("ended");
		});
	});

	it("claims stream dispatch exclusively for the manager", async () => {
		await withClient(connect, async (client) => {
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
	});

	it("refuses a manager over a client that already serves a shared handler", async () => {
		await withClient(connect, async (client) => {
			client.serve(() => undefined);
			const shared = expect.objectContaining({
				code: "ServeDispatchShared",
			});

			expect(() => managerOver(client)).toThrow(shared);
		});
	});

	it("fans one publish out to every subscriber", async () => {
		await withClient(connect, async (first) => {
			await withClient(connect, async (second) => {
				const topic = testTopic("fanout");
				const firstManager = managerOver(first);
				const firstUpdates = (await subscribed(firstManager, topic))[
					Symbol.asyncIterator
				]();
				const secondUpdates = (
					await subscribed(managerOver(second), topic)
				)[Symbol.asyncIterator]();

				await publish(firstManager, topic, "tick");

				expect(await nextReceived(firstUpdates)).toEqual({
					payload: "tick",
					order: 1n,
				});
				expect(await nextReceived(secondUpdates)).toEqual({
					payload: "tick",
					order: 1n,
				});
			});
		});
	});

	it("stops delivery after unsubscribe", async () => {
		await withClient(connect, async (leaver) => {
			await withClient(connect, async (stayer) => {
				const topic = testTopic("churn");
				const leaverManager = managerOver(leaver);
				const leaverSubscription = await subscribed(
					leaverManager,
					topic,
				);
				const leaverUpdates =
					leaverSubscription[Symbol.asyncIterator]();
				const stayerUpdates = (
					await subscribed(managerOver(stayer), topic)
				)[Symbol.asyncIterator]();

				await publish(leaverManager, topic, "before");
				expect(await nextReceived(leaverUpdates)).toEqual({
					payload: "before",
					order: 1n,
				});

				await leaverSubscription.unsubscribe();
				await publish(leaverManager, topic, "after");

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
		});
	});

	it("drops an update already in flight when unsubscribe lands", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("in-flight");
			const delivered: string[] = [];

			let releaseDecrypt!: () => void;
			const parked = new Promise<void>((resolve) => {
				releaseDecrypt = resolve;
			});

			let decrypting = false;

			/*
			 * A BYO decryptor that parks until released: the controllable
			 * async window an envelope layer opens inside a delivery, so
			 * unsubscribe can land while the update is in flight.
			 */
			const key = ENGINE.aes256Gcm(STACK.topicSecret);
			const stalled: BodyDecryptor = {
				decrypt: async (sealed) => {
					decrypting = true;
					await parked;
					return key.decrypt(sealed);
				},
			};

			await manager.subscribe(topic, {
				envelope: ENGINE.envelope(ENGINE.opaque).sealed(stalled),
				onUpdate: (message) => {
					delivered.push(DECODER.decode(message));
				},
			});
			await manager.publish(topic, ENCODER.encode("late"), {
				envelope: ENGINE.envelope(ENGINE.opaque).sealed(key),
			});

			await expect.poll(() => decrypting).toBe(true);
			await manager.unsubscribe(topic);

			releaseDecrypt();

			/*
			 * Give the released delivery every chance to (wrongly) reach
			 * the handler before asserting the unsubscribe fence held.
			 */
			await new Promise((resolve) => {
				setTimeout(resolve, 100);
			});
			expect(delivered).toEqual([]);
		});
	});

	it("rejects a forbidden topic with PermissionDenied", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const denied = manager.subscribe("forbidden/keys", {
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
	});

	it("holds topic names to the same octet limit as the server", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const longest = testTopic("limit/").padEnd(WIRE.topicMaxLen, "a");
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
	});

	it("replays subscriptions onto a replacement connection", async () => {
		const first = await connect();
		const manager = managerOver(first);
		const topic = testTopic("reattach");
		const subscription = await subscribed(manager, topic);
		const updates = subscription[Symbol.asyncIterator]();

		try {
			await publish(manager, topic, "before");
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

			await publish(manager, topic, "after");
			expect(await nextReceived(updates)).toEqual({
				payload: "after",
				order: 2n,
			});
		} finally {
			await second.close();
		}
	});

	it("reports a delivery gap through onGap after a DropOldest eviction", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("burst");
			const orders: bigint[] = [];
			const gaps: [string, bigint, bigint][] = [];

			/*
			 * Every update handler parks on this latch, so the first
			 * update stays unacknowledged while the burst overfills the
			 * server's delivery queue.
			 */
			let release!: () => void;
			const released = new Promise<void>((resolve) => {
				release = resolve;
			});

			await manager.subscribe(topic, {
				codec: ENGINE.opaque,
				onUpdate: async (_payload, update) => {
					orders.push(update.order);
					await released;
				},
				onGap: (gapTopic, expected, arrived) => {
					gaps.push([gapTopic, expected, arrived]);
				},
			});

			await publish(manager, topic, "1");
			await expect.poll(() => orders).toEqual([1n]);

			/*
			 * With update 1 held in flight, a burst one past the queue
			 * bound fills the queue and evicts update 2.
			 */
			for (
				let order = 2;
				order <= STACK.pubsubQueueCapacity + 2;
				order += 1
			) {
				await publish(manager, topic, String(order));
			}

			release();
			await expect.poll(() => gaps).toEqual([[topic, 2n, 3n]]);
			/*
			 * The eviction dropped update 2: order 3 follows order 1.
			 */
			await expect.poll(() => orders.slice(0, 2)).toEqual([1n, 3n]);
		});
	});

	it("relays a signed inner frame with its metadata end to end", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("orders");
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
			expect(() => {
				relayed.verify(SIGNING_KEY.verifyingKey());
			}).not.toThrow();
			expect(DECODER.decode(relayed.id)).toBe("order-42");
			expect(relayed.order).toBe(7n);
			expect(relayed.priority).toBe(ENGINE.MessagePriority.Expedited);
			expect(relayed.lifetime).toBe(60n);
			expect(relayed.message(ENGINE.opaque)).toEqual(fill);
		});
	});

	it("relays a sealed inner frame the broker cannot read", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("sealed");

			/*
			 * One declaration serves both directions: publish builds a
			 * signed, sealed inner frame, and every unwrapped update is
			 * PROVEN to carry the publisher's signature and the topic
			 * seal - a cleartext or unsigned frame rejects instead.
			 */
			const cipher = ENGINE.aes256Gcm(STACK.topicSecret);
			const secrets = ENGINE.envelope(ENGINE.opaque)
				.signed(SIGNING_KEY)
				.sealed(cipher);

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
	});

	it("routes non-topic server streams to the fallback", async () => {
		await withClient(connect, async (client) => {
			const notices: string[] = [];
			const ports = ClientPorts.split(client);
			const manager = new SubscriptionManager(ports, {
				fallback: (update) => {
					notices.push(DECODER.decode(update.id));
					return undefined;
				},
			});

			const empty = new Uint8Array(0);
			const poke = await ENGINE.frameBuilder(empty)
				.withId("poke")
				.build();

			await client.emit(poke);

			await expect.poll(() => notices).toEqual(["notice"]);
			expect(manager.topics).toEqual([]);
		});
	});
});

describe("SubscriptionManager commands against the dockerized demo server", () => {
	it("two publishes on one topic, the first past the initial stream credit, reach a subscriber in send order", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("credit-order");
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
	});

	it("leaves a newer subscription live when an old handle unsubscribes again", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("newer");
			const old = await subscribed(manager, topic);
			await old.unsubscribe();
			const current = await subscribed(manager, topic);
			const updates = current[Symbol.asyncIterator]();

			await old.unsubscribe();
			await publish(manager, topic, "kept");

			expect(current.state).toBe("live");
			expect(await nextReceived(updates)).toEqual({
				payload: "kept",
				order: 1n,
			});
		});
	});

	it("a break out of a subscription unsubscribes it", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const subscription = await subscribed(manager, testTopic("break"));
			const updates = subscription[Symbol.asyncIterator]();

			await updates.return?.();

			expect(subscription.state).toBe("ended");
			expect(manager.topics).toEqual([]);
		});
	});

	it("a handler subscription has no iterator", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("handler");

			const subscription = await manager.subscribe(topic, HANDLED);
			expectTypeOf(subscription).toEqualTypeOf<HandlerSubscription>();
			expectTypeOf(subscription).not.toHaveProperty(Symbol.asyncIterator);
			expect(Symbol.asyncIterator in subscription).toBe(false);
		});
	});

	it("refuses a second iterator as AlreadyIterating", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("iterated");
			const subscription = await subscribed(manager, topic);
			subscription[Symbol.asyncIterator]();

			const refusal = expect.objectContaining({
				code: "AlreadyIterating",
			});
			expect(() => subscription[Symbol.asyncIterator]()).toThrow(refusal);
		});
	});

	it("refuses a second subscribe to a live topic as AlreadySubscribed", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("twice");
			await subscribed(manager, topic);

			const second = manager.subscribe(topic, OPAQUE);
			await expect(second).rejects.toMatchObject({
				code: "AlreadySubscribed",
			});
		});
	});

	it("refuses to unsubscribe from an invalid topic name", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const left = manager.unsubscribe("");
			await expect(left).rejects.toMatchObject({ code: "Empty" });
		});
	});
});

describe("SubscriptionManager reattach against the dockerized demo server", () => {
	it("the lanes of one manager defer at most MAX_DEFERRED commands across their topics", async () => {
		const client = await connect();
		const manager = managerOver(client);
		await client.close();
		const share = MAX_DEFERRED / 2;

		await deferEvery(manager, testTopic("budget-first"), share);
		await deferEvery(manager, testTopic("budget-second"), share);

		const third = testTopic("budget-third");
		const refused = manager.publish(third, HELD_BODY, OPAQUE);

		await expect(refused).rejects.toMatchObject({ code: "DeferralFull" });
		await manager[Symbol.asyncDispose]();
	});

	it("defers a subscribe on a lost connection, and the reattach makes it live", async () => {
		const first = await connect();
		const manager = managerOver(first);

		await first.close();

		const topic = testTopic("deferred-subscribe");
		const subscription = await subscribed(manager, topic);
		const deferred = subscription.state;
		const updates = subscription[Symbol.asyncIterator]();

		const second = await connect();
		try {
			await manager.reattach(ClientPorts.split(second));
			await publish(manager, topic, "replayed");

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
		const topic = testTopic("deferred-publish");
		const subscription = await subscribed(manager, topic);
		const updates = subscription[Symbol.asyncIterator]();
		await first.close();
		await publish(manager, topic, "deferred");

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
		const topic = testTopic("deferred-unsubscribe");
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

			await publish(manager, topic, "fresh");

			expect(await nextReceived(updates)).toEqual({
				payload: "fresh",
				order: 1n,
			});
		} finally {
			await second.close();
		}
	});
});

describe("SubscriptionManager disposal against the dockerized demo server", () => {
	it("a disposed manager detaches its serve handler", async () => {
		await withClient(connect, async (client) => {
			const notices: string[] = [];
			const ports = ClientPorts.split(client);
			const manager = new SubscriptionManager(ports, {
				fallback: (update) => {
					notices.push(DECODER.decode(update.id));
					return undefined;
				},
			});

			const empty = new Uint8Array(0);
			const poke = await ENGINE.frameBuilder(empty)
				.withId("poke")
				.build();

			await manager[Symbol.asyncDispose]();

			const poked = client.emit(poke);
			await expect(poked).rejects.toMatchObject({ code: "Unavailable" });
			expect(notices).toEqual([]);
		});
	});

	it("a disposed manager ends every subscription", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const topic = testTopic("disposed-end");
			const subscription = await manager.subscribe(topic, HANDLED);

			await manager[Symbol.asyncDispose]();

			expect(subscription.state).toBe("ended");
			expect(manager.topics).toEqual([]);
		});
	});

	it.each(DISPOSED_CALLS)(
		"a disposed manager refuses $call as Disposed",
		async ({ run }) => {
			await withClient(connect, async (client) => {
				const manager = managerOver(client);
				await manager[Symbol.asyncDispose]();

				const refused = run(manager, client);

				await expect(refused).rejects.toThrow(DISPOSED);
			});
		},
	);

	it("a disposed manager installs no handler on reattach", async () => {
		await withClient(connect, async (first) => {
			await withClient(connect, async (second) => {
				const manager = managerOver(first);
				await manager[Symbol.asyncDispose]();

				const reattached = manager.reattach(ClientPorts.split(second));
				await expect(reattached).rejects.toThrow(DISPOSED);
				expect(() => {
					second.serve(() => undefined);
				}).not.toThrow();
			});
		});
	});
});

describe("SubscriptionManager handles against the dockerized demo server", () => {
	it("an acknowledged publish frees the copy of its codec", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const name = new KeptName();
			const source = { codec: codecNaming(name) };
			const topic = testTopic("acknowledged-copy");

			await manager.publish(topic, HELD_BODY, source);

			expect(allFreed(name)).toBe(true);
		});
	});

	it("a refused publish frees the copy of its codec", async () => {
		await withClient(connect, async (client) => {
			const manager = managerOver(client);
			const name = new KeptName();
			const source = { codec: codecNaming(name) };
			const topic = `forbidden/${RUN}/copy`;

			const refused = manager.publish(topic, HELD_BODY, source);
			await expect(refused).rejects.toMatchObject({
				code: "PermissionDenied",
			});
			expect(allFreed(name)).toBe(true);
		});
	});

	it("a deferred publish keeps its copy until the manager drops it", async () => {
		const client = await connect();
		const manager = managerOver(client);

		await client.close();

		const name = new KeptName();
		const source = { codec: codecNaming(name) };
		const topic = testTopic("deferred-copy");

		await manager.publish(topic, HELD_BODY, source);
		const keptWhileDeferred = noneFreed(name);
		await manager[Symbol.asyncDispose]();

		expect(keptWhileDeferred).toBe(true);
		expect(allFreed(name)).toBe(true);
	});

	it("a disposal over a publish in flight resolves once the client closes", async () => {
		const client = await connect();
		const manager = managerOver(client);
		const topic = testTopic("dispose-close");
		const publishing = manager.publish(topic, PAST_INITIAL_CREDIT, OPAQUE);

		const disposing = manager[Symbol.asyncDispose]();
		await client.close();

		await expect(disposing).resolves.toBeUndefined();
		await expect(publishing).resolves.toBeUndefined();
	});

	it("a disposal waits for a publish in flight, which settles and drops its copy", async () => {
		const client = await connect();
		const manager = managerOver(client);
		const name = new KeptName();
		const source = { codec: codecNaming(name) };
		const topic = testTopic("in-flight-copy");

		const publishing = manager.publish(topic, HELD_BODY, source);
		const closing = client.close();
		const disposing = manager[Symbol.asyncDispose]();

		await Promise.all([publishing, closing, disposing]);

		expect(allFreed(name)).toBe(true);
	});
});
