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
export {
	ClientPorts,
	MAX_DEFERRED,
	PayloadShape,
	SubscriptionError,
	SubscriptionManager,
} from "./manager.js";
export type {
	CommandLane,
	CommandPort,
	DeferralBudget,
	EndHandler,
	GapHandler,
	HandlerSubscription,
	IteratingSubscription,
	ManagerOptions,
	PayloadSource,
	ServePort,
	ShapeUse,
	SubscribeOptions,
	Subscriber,
	SubscriptionErrorCode,
	SubscriptionObservers,
	SubscriptionState,
	Update,
	UpdateHandler,
} from "./manager.js";
export { Command, Topic, TopicError } from "./topic.js";
export type { CommandBody, TopicErrorCode } from "./topic.js";
