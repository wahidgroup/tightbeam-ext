/**
 * The names that the TypeScript sample of `docs/pubsub.md` takes from its
 * surroundings, as `src/docs.test.ts` compiles it.
 */
import type { ClientPorts as Ports, SubscriptionManager as Manager } from "@wahidgroup/tightbeam-pubsub-client";
import type { Engine, Frame, TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";

declare global {
	const SubscriptionManager: typeof Manager;
	const ClientPorts: typeof Ports;

	function render(...values: unknown[]): void;
	function handleAppStream(update: Frame): Promise<undefined>;
	const engine: Engine;
	const client: TightbeamWsClient;
	const payload: Uint8Array;
}
