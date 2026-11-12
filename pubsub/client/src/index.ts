/**
 * Topic subscriptions for the tightbeam WebSocket client. The page
 * `docs/pubsub-client.md` specifies the package.
 */

export { ClientPorts, MAX_DEFERRED, SubscriptionError, SubscriptionManager } from "./manager.js";
export type {
	CommandPort,
	EndHandler,
	GapHandler,
	HandlerSubscription,
	IteratingSubscription,
	ManagerOptions,
	PublishPayload,
	ServePort,
	SubscribeOptions,
	SubscribePayload,
	SubscriptionErrorCode,
	SubscriptionObservers,
	SubscriptionState,
	Update,
	UpdateHandler,
} from "./manager.js";
export type { Gap } from "./gate.js";
export { Command, Topic, TopicError } from "./topic.js";
export type { CommandPayload, TopicErrorCode } from "./topic.js";
