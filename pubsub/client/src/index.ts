/**
 * Topic subscriptions for the tightbeam WebSocket client.
 *
 * Pairs with the `tightbeam-pubsub` Rust crate: `sub/<topic>` and
 * `unsub/<topic>` command streams manage membership, updates arrive as
 * server-initiated streams whose frame id is the topic, and
 * `end/<topic>` completes a subscription when the server quiesces.
 */

export { TopicGate } from "./gate.js";
export type { GateVerdict } from "./gate.js";
export { SubscriptionManager } from "./manager.js";
export type {
	EndHandler,
	GapHandler,
	ManagerOptions,
	SubscribeOptions,
	Subscription,
	SubscriptionObservers,
	SubscriptionState,
	Update,
	UpdateHandler,
} from "./manager.js";
export {
	END_PREFIX,
	PUB_PREFIX,
	SUB_PREFIX,
	UNSUB_PREFIX,
	assertTopic,
} from "./topic.js";
