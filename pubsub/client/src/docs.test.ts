import { describe, expectTypeOf, it } from "vitest";

import type {
	Engine,
	Frame,
	MessageCodec,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	TightbeamWsClient,
} from "@wahidgroup/tightbeam-ws-client";

import { ClientPorts, SubscriptionManager } from "./index.js";

interface Order {
	symbol: string;
	quantity: number;
}

interface Note {
	author: string;
	text: string;
}

declare function render(...values: unknown[]): void;
declare function apply(...values: unknown[]): void;
declare function expedite(...values: unknown[]): void;
declare function refetchSnapshot(...values: unknown[]): void;
declare function asOrder(value: unknown): Order;
declare function connect(): Promise<TightbeamWsClient>;
declare function handleAppStream(update: Frame): Promise<undefined>;
declare const engine: Engine;
declare const client: TightbeamWsClient;
declare const manager: SubscriptionManager;
declare const encoded: Uint8Array;
declare const payload: Uint8Array;
declare const signingKey: Secp256k1SigningKey;
declare const publisherKey: Secp256k1VerifyingKey;
declare const received: Frame;
declare const Orders: MessageCodec<Order>;
declare const Notes: MessageCodec<Note>;
declare const topicKey: Uint8Array;
declare const topicKeyId: Uint8Array;
declare const salt: Uint8Array;

describe("docs/pubsub-client.md", () => {
	it("Subscriptions", () => {
		async function sample(): Promise<void> {
			const prices = await manager.subscribe("prices", {
				codec: engine.opaque,
				onUpdate: (payload, update, topic) => {
					render(topic, payload, update.order);
				},
				onEnd: (topic) => {
					console.log(`${topic} completed`);
				},
			});

			// Later: emits `unsub/prices` and stops local dispatch.
			await prices.unsubscribe();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Payload shapes, frames as payloads", () => {
		async function sample(): Promise<void> {
			interface Order {
				symbol: string;
				quantity: number;
			}

			// Any MessageCodec<T> types the inner body (the ws client's "Typed
			// messages" section). This one lifts JSON, and asOrder runtime-validates.
			const Orders: MessageCodec<Order> = engine.wrapping({
				encode: (order) =>
					new TextEncoder().encode(JSON.stringify(order)),
				decode: (payload) =>
					asOrder(JSON.parse(new TextDecoder().decode(payload))),
			});

			// Publisher: a typed body inside a signed frame.
			const inner = await engine
				.frameBuilder()
				.withMessage(Orders, { symbol: "BTC", quantity: 42 })
				.withId("order-42")
				.withOrder(7)
				.withPriority(engine.MessagePriority.Expedited)
				.withLifetime(60)
				.withSigner(signingKey)
				.build();
			await manager.publish("orders", inner, { codec: engine.framed });

			// Subscriber: the whole Frame surface is live on each update.
			const orders = await manager.subscribe("orders", {
				codec: engine.framed,
			});
			for await (const { message: received, frame: wrapper } of orders) {
				received.verify(publisherKey); // end-to-end publisher authenticity

				// The publisher's metadata, distinct from the wrapper's stamps.
				if (received.priority === engine.MessagePriority.Expedited) {
					expedite(received.id, received.lifetime);
				}

				apply(received.message(Orders), wrapper.order); // Order
			}
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Payload shapes, frames as payloads opened and checked", () => {
		async function sample(): Promise<void> {
			const order = await received.open(Orders, {
				opener: engine.aes256Gcm({ key: topicKey, keyId: topicKeyId }),
			});
			const verdict = await received.messageCommitmentVerdict(
				engine.salt(salt),
			); // "verified"

			expectTypeOf([order, verdict]).toBeArray();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Payload shapes, envelopes end to end", () => {
		// The publisher of this sample signs with `publisherKey`.
		async function sample(
			publisherKey: Secp256k1SigningKey,
		): Promise<void> {
			const notes = engine
				.envelope(Notes) // the Orders-style typed codec above
				.signed(publisherKey)
				.sealed(engine.aes256Gcm({ key: topicKey, keyId: topicKeyId }));

			// Publisher: one call builds the signed, sealed inner frame.
			await manager.publish(
				"notes",
				{ author: "board", text: "hello" },
				{ envelope: notes },
			);

			// Subscriber: `note` arrives verified, opened, and decoded.
			await manager.subscribe("notes", {
				envelope: notes,
				onUpdate: (note, wrapper) => {
					render(note, wrapper.order);
				},
			});
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Publish", () => {
		async function sample(): Promise<void> {
			await manager.publish("prices", encoded, { codec: engine.opaque }); // emits `pub/prices`
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Ordering and gaps", () => {
		async function sample(): Promise<void> {
			await manager.subscribe("ticks", {
				codec: engine.opaque,
				onUpdate: (payload) => apply(payload),
				onGap: (topic, expected, received) => {
					refetchSnapshot(topic, expected, received);
				},
			});
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Reconnect replay", () => {
		async function sample(): Promise<void> {
			let client = await connect();
			const manager = new SubscriptionManager(ClientPorts.split(client));
			await manager.subscribe("prices", {
				codec: engine.opaque,
				onUpdate: render,
			});

			// The connection drops and the app decides to reconnect.
			await client.close();

			client = await connect();
			await manager.reattach(ClientPorts.split(client));
			// `sub/prices` replayed, gate re-baselined, updates flowing again.
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Unmatched pushes", () => {
		function sample(): void {
			const manager = new SubscriptionManager(ClientPorts.split(client), {
				fallback: async (update) => handleAppStream(update),
			});

			expectTypeOf(manager).toEqualTypeOf<SubscriptionManager>();
		}

		expectTypeOf(sample).toBeFunction();
	});
});

describe("docs/pubsub.md", () => {
	it("Wire convention", () => {
		async function sample(): Promise<void> {
			const manager = new SubscriptionManager(ClientPorts.split(client), {
				// Non-topic server pushes. Unmatched ids answer Unimplemented.
				fallback: async (update) => handleAppStream(update),
			});

			// Registers the topic route, then emits `sub/prices`.
			const prices = await manager.subscribe("prices", {
				codec: engine.opaque,
			});
			for await (const { message, frame } of prices) {
				render(message, frame.order);
			}

			await manager.publish("prices", payload, { codec: engine.opaque }); // emits `pub/prices`
			await manager.unsubscribe("prices"); // emits `unsub/prices`
		}

		expectTypeOf(sample).toBeFunction();
	});
});
