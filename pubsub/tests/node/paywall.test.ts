/**
 * Pubsub demo compose always enables the session-budget paywall.
 * These cases prove settlement failure and a paid dial on that stack.
 */

import { describe, expect, it } from "vitest";

import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";
import {
	ClientPorts,
	SubscriptionManager,
} from "@wahidgroup/tightbeam-pubsub-client";

import { certBytes, demoIdentity } from "#ws-env";
import { mutualSessionOptions, withClient } from "#ws-fixtures";
import { NobleTransportSigner } from "#ws-signer";
import { STACK } from "./stack.js";

const ENGINE = await TightbeamWsClient.init();

describe("pubsub mutual paywall", () => {
	it("exposes usableSendBudget after a paid handshake", async () => {
		await withClient(
			() =>
				ENGINE.connectMutual(
					STACK.pubsubEndpoint,
					demoIdentity(),
					mutualSessionOptions(STACK.paywall),
				),
			async (client) => {
				expect(client.usableSendBudget).toBeTypeOf("number");
				expect(client.usableSendBudget).toBeGreaterThan(0);
			},
		);
	});

	it("closes the session when settlement is unpaid", async () => {
		const client = await ENGINE.connectMutual(
			STACK.pubsubEndpoint,
			demoIdentity(),
			mutualSessionOptions(STACK.paywall, 0),
		);

		await expect(client.closed).resolves.toBeTruthy();
	});

	it("authenticates through an external transport signer under the paywall", async () => {
		const signer = new NobleTransportSigner(
			ENGINE,
			certBytes("client.key"),
		);

		await withClient(
			() =>
				ENGINE.connectMutual(
					STACK.pubsubEndpoint,
					demoIdentity(signer),
					mutualSessionOptions(STACK.paywall),
				),
			async (client) => {
				const ports = ClientPorts.split(client);
				const manager = new SubscriptionManager(ports);
				const topic = `e2e/signer/${Date.now()}`;
				const subscription = await manager.subscribe(topic, {
					codec: ENGINE.opaque,
				});

				const updates = subscription[Symbol.asyncIterator]();
				await manager.publish(topic, new TextEncoder().encode("ok"), {
					codec: ENGINE.opaque,
				});

				const next = await updates.next();
				expect(next.done).toBe(false);
				expect(signer.signatures).toBe(2);

				await subscription.unsubscribe();
			},
		);
	});
});
