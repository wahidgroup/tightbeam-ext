import { describe, expectTypeOf, it } from "vitest";

import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";

import { ClientPorts, SubscriptionManager } from "./index.js";

/**
 * The TypeScript sample of the package README, one case per section. Each
 * case holds its sample verbatim inside a function that the case never calls:
 * `tsc` compiles every sample under the typecheck of the suite, and a sample
 * that drifts from the API fails the typecheck. The samples of
 * `docs/pubsub-client.md` and `docs/pubsub.md` compile in `docs.test.ts`.
 */

declare function render(...values: unknown[]): void;

describe("README samples", () => {
	it("quick start", () => {
		async function sample(): Promise<void> {
			const engine = await TightbeamWsClient.init();
			const client = await engine.connectCleartext("ws://localhost:9110");
			const ports = ClientPorts.split(client);
			const manager = new SubscriptionManager(ports);

			// Without an onUpdate handler, the subscription is async-iterable.
			const prices = await manager.subscribe("prices", {
				codec: engine.opaque,
			});
			for await (const { message, frame } of prices) {
				render(message, frame.order);
			}
			// Iteration ends when the topic completes or unsubscribes. A break out of
			// the loop unsubscribes the topic.
		}

		expectTypeOf(sample).toBeFunction();
	});
});
