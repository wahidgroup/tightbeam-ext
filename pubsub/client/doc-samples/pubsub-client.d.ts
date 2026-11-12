/**
 * The names that the samples of `docs/pubsub-client.md` take from their
 * surroundings, as `src/docs.test.ts` compiles them.
 */
import type { ClientPorts as Ports, SubscriptionManager as Manager } from "@wahidgroup/tightbeam-pubsub-client";
import type {
	Engine,
	Frame,
	MessageCodec,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	TightbeamWsClient,
} from "@wahidgroup/tightbeam-ws-client";

declare global {
	interface Order {
		symbol: string;
		quantity: number;
	}

	interface Note {
		author: string;
		text: string;
	}

	const SubscriptionManager: typeof Manager;
	const ClientPorts: typeof Ports;

	function render(...values: unknown[]): void;
	function apply(...values: unknown[]): void;
	function expedite(...values: unknown[]): void;
	function refetchSnapshot(...values: unknown[]): void;
	function asOrder(value: unknown): Order;
	function connect(): Promise<TightbeamWsClient>;
	function handleAppStream(update: Frame): Promise<undefined>;
	const engine: Engine;
	const client: TightbeamWsClient;
	const manager: Manager;
	const encoded: Uint8Array;
	const signingKey: Secp256k1SigningKey;
	const publisherKey: Secp256k1VerifyingKey;
	const received: Frame;
	const Orders: MessageCodec<Order>;
	const Notes: MessageCodec<Note>;
	const topicKey: Uint8Array;
	const topicKeyId: Uint8Array;
	const salt: Uint8Array;
}
