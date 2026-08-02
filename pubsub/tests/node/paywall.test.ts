/**
 * Pubsub demo compose always enables the session-budget paywall.
 * These cases prove settlement failure and a paid dial on that stack.
 */

import { describe, expect, it } from "vitest";

import { Opaque, TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";
import { SubscriptionManager } from "@wahidgroup/tightbeam-pubsub-client";

import { withClient } from "#ws-harness";
import { NobleTransportSigner } from "#ws-signer";
import { certBytes, mutualSessionOptions, pubsubEndpoint } from "./env.js";

describe("pubsub mutual paywall", () => {
	it("exposes usableSendBudget after a paid handshake", async () => {
		await withClient(
			() =>
				TightbeamWsClient.connectMutual(
					pubsubEndpoint,
					certBytes("server.cert.der"),
					certBytes("client.cert.der"),
					certBytes("client.key"),
					mutualSessionOptions(),
				),
			async (client) => {
				expect(client.usableSendBudget).toBeTypeOf("number");
				expect(client.usableSendBudget).toBeGreaterThan(0);
			},
		);
	});

	it("closes the session when settlement is unpaid", async () => {
		const client = await TightbeamWsClient.connectMutual(
			pubsubEndpoint,
			certBytes("server.cert.der"),
			certBytes("client.cert.der"),
			certBytes("client.key"),
			{
				budgets: { clientToServer: 4096, serverToClient: 4096 },
				approveReceipt: () => undefined,
			},
		);

		await expect(client.closed).resolves.toBeTruthy();
	});

	it("authenticates through an external transport signer under the paywall", async () => {
		const signer = new NobleTransportSigner(certBytes("client.key"));

		await withClient(
			() =>
				TightbeamWsClient.connectMutual(
					pubsubEndpoint,
					certBytes("server.cert.der"),
					certBytes("client.cert.der"),
					signer,
					mutualSessionOptions(),
				),
			async (client) => {
				const manager = new SubscriptionManager(client);
				const topic = `e2e/signer/${Date.now()}`;
				const subscription = await manager.subscribe(topic, {
					codec: Opaque,
				});
				const updates = subscription[Symbol.asyncIterator]();
				await manager.publish(
					topic,
					new TextEncoder().encode("ok"),
					Opaque,
				);
				const next = await updates.next();
				expect(next.done).toBe(false);
				expect(signer.signatures).toBe(2);
				await subscription.unsubscribe();
			},
		);
	});
});
