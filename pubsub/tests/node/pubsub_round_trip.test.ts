import { describe, expect, it } from "vitest";

import {
	Aes256Gcm,
	Framed,
	MessagePriority,
	Opaque,
	Secp256k1SigningKey,
	TightbeamWsClient,
	envelope,
	frame,
} from "@wahidgroup/tightbeam-ws-client";
import type { Subscription, Update } from "@wahidgroup/tightbeam-pubsub-client";
import { SubscriptionManager } from "@wahidgroup/tightbeam-pubsub-client";

import { withClient } from "#ws-harness";
import { certBytes, pubsubEndpoint, pubsubQueueCapacity } from "./env.js";

const ENCODER = new TextEncoder();

const DECODER = new TextDecoder();

/**
 * The publisher's frame-level signing key for the frame-in-frame tests.
 */
const SIGNING_KEY = Secp256k1SigningKey.fromBytes(new Uint8Array(32).fill(1));

/**
 * The shared body key for the sealed frame-in-frame test.
 */
const TOPIC_KEY = new Uint8Array(32).fill(7);

/**
 * The demo server's registry is shared by every connection of the whole
 * suite run, so each test isolates itself on its own topic.
 */
const RUN = Math.random().toString(36).slice(2, 10);

function testTopic(name: string): string {
	return `e2e/${RUN}/${name}`;
}

function connect(): Promise<TightbeamWsClient> {
	return TightbeamWsClient.connect(
		pubsubEndpoint,
		certBytes("server.cert.der"),
	);
}

/**
 * Publish `payload` on `topic` through the wire's `pub/` command.
 */
async function publish(
	manager: SubscriptionManager,
	topic: string,
	payload: string,
): Promise<void> {
	await manager.publish(topic, ENCODER.encode(payload), Opaque);
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
): Promise<Subscription<Uint8Array>> {
	const subscription = await manager.subscribe(topic, { codec: Opaque });
	return subscription;
}

describe("pub/sub round-trips against the dockerized demo server", () => {
	it("delivers published updates in dense order", async () => {
		await withClient(connect, async (client) => {
			const manager = new SubscriptionManager(client);
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
			const manager = new SubscriptionManager(client);
			const topic = testTopic("poisoned");
			const delivered: string[] = [];
			const gaps: { expected: bigint; received: bigint }[] = [];

			await manager.subscribe(topic, {
				codec: Opaque,
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

	it("still delivers the gap-revealing update when onGap throws", async () => {
		await withClient(connect, async (client) => {
			const manager = new SubscriptionManager(client);
			const topic = testTopic("gap-throw");
			const delivered: string[] = [];

			await manager.subscribe(topic, {
				codec: Opaque,
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
			const manager = new SubscriptionManager(client);

			const subscription = await subscribed(manager, testTopic("state"));
			expect(subscription.state).toBe("live");

			await subscription.unsubscribe();
			expect(subscription.state).toBe("ended");
		});
	});

	it("claims stream dispatch exclusively for the manager", async () => {
		await withClient(connect, async (client) => {
			void new SubscriptionManager(client);

			expect(() => {
				client.serve(() => undefined);
			}).toThrow("exclusively claimed");
		});
	});

	it("fans one publish out to every subscriber", async () => {
		await withClient(connect, async (first) => {
			await withClient(connect, async (second) => {
				const topic = testTopic("fanout");
				const firstManager = new SubscriptionManager(first);
				const firstUpdates = (await subscribed(firstManager, topic))[
					Symbol.asyncIterator
				]();
				const secondUpdates = (
					await subscribed(new SubscriptionManager(second), topic)
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
				const leaverManager = new SubscriptionManager(leaver);
				const leaverSubscription = await subscribed(
					leaverManager,
					topic,
				);
				const leaverUpdates =
					leaverSubscription[Symbol.asyncIterator]();
				const stayerUpdates = (
					await subscribed(new SubscriptionManager(stayer), topic)
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

	it("rejects a forbidden topic with PermissionDenied", async () => {
		await withClient(connect, async (client) => {
			const manager = new SubscriptionManager(client);

			const denied = manager.subscribe("forbidden/keys", {
				codec: Opaque,
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

	it("replays subscriptions onto a replacement connection", async () => {
		const first = await connect();
		const manager = new SubscriptionManager(first);
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
			first.close();
		}

		const second = await connect();
		try {
			await manager.reattach(second);
			expect(subscription.state).toBe("live");

			await publish(manager, topic, "after");
			expect(await nextReceived(updates)).toEqual({
				payload: "after",
				order: 2n,
			});
		} finally {
			second.close();
		}
	});

	it("reports a delivery gap through onGap after a DropOldest eviction", async () => {
		await withClient(connect, async (client) => {
			const manager = new SubscriptionManager(client);
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
				codec: Opaque,
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
			for (let order = 2; order <= pubsubQueueCapacity + 2; order += 1) {
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
			const manager = new SubscriptionManager(client);
			const topic = testTopic("orders");
			const subscription = await manager.subscribe(topic, {
				codec: Framed,
			});
			const updates = subscription[Symbol.asyncIterator]();

			const fill = ENCODER.encode("fill 42 @ 101.5");
			const inner = await frame(fill)
				.withId("order-42")
				.withOrder(7)
				.withPriority(MessagePriority.Expedited)
				.withLifetime(60)
				.withSigner(SIGNING_KEY)
				.build();
			await manager.publish(topic, inner, Framed);

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
			expect(relayed.priority).toBe(MessagePriority.Expedited);
			expect(relayed.lifetime).toBe(60n);
			expect(relayed.message(Opaque)).toEqual(fill);
		});
	});

	it("relays a sealed inner frame the broker cannot read", async () => {
		await withClient(connect, async (client) => {
			const manager = new SubscriptionManager(client);
			const topic = testTopic("sealed");

			/*
			 * One declaration serves both directions: publish builds a
			 * signed, sealed inner frame, and every unwrapped update is
			 * PROVEN to carry the publisher's signature and the topic
			 * seal - a cleartext or unsigned frame rejects instead.
			 */
			const secrets = envelope(Opaque)
				.signed(SIGNING_KEY)
				.sealed(Aes256Gcm.fromKey(TOPIC_KEY));

			const subscription = await manager.subscribe(topic, {
				envelope: secrets,
			});
			const updates = subscription[Symbol.asyncIterator]();

			const secret = ENCODER.encode("for subscribers only");
			await manager.publish(topic, secret, secrets);

			const update = await nextUpdate(updates);
			expect(update.message).toEqual(secret);
			expect(DECODER.decode(update.frame.id)).toBe(topic);
			expect(update.frame.order).toBe(1n);
		});
	});

	it("routes non-topic server streams to the fallback", async () => {
		await withClient(connect, async (client) => {
			const notices: string[] = [];
			const manager = new SubscriptionManager(client, {
				fallback: (update) => {
					notices.push(DECODER.decode(update.id));
					return undefined;
				},
			});

			const poke = await frame(new Uint8Array(0)).withId("poke").build();
			await client.emit(poke);

			await expect.poll(() => notices).toEqual(["notice"]);
			expect(manager.topics).toEqual([]);
		});
	});

	/*
	 * Quiesce drains the shared registry for good, so this runs last.
	 */
	it("completes subscriptions and drains on quiesce", async () => {
		await withClient(connect, async (client) => {
			const manager = new SubscriptionManager(client);
			const topic = testTopic("final");
			const completions: string[] = [];
			const subscription = await manager.subscribe(topic, {
				codec: Opaque,
				onUpdate: () => {
					throw new Error("nothing is published on the final topic");
				},
				onEnd: (ended) => {
					completions.push(ended);
				},
			});

			/*
			 * The server pushes end/<topic>, waits for it to flush, then
			 * drains the connection. The drain stops the writer before the
			 * quiesce response, so the emit is aborted once the GoAway
			 * reason surfaces.
			 */
			const quiesce = await frame(new Uint8Array(0))
				.withId("quiesce")
				.build();
			const controller = new AbortController();
			const pending = client.emit(quiesce, { signal: controller.signal });

			await expect.poll(() => completions).toEqual([topic]);
			expect(manager.topics).toEqual([]);
			expect(subscription.state).toBe("ended");
			await expect.poll(() => client.goawayReason).toBe("Shutdown");

			controller.abort(new Error("drain observed"));
			await expect(pending).rejects.toThrow("drain observed");
		});
	});
});
