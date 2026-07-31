import { describe, expect, it } from "vitest";

import { TightbeamWsClient, frame } from "@wahidgroup/tightbeam-ws-client";

import { certBytes, muxMutualEndpoint, mutualSessionOptions } from "../env.js";
import { emitOrFail, withClient } from "./harness.js";

describe("Node mutual paywall", () => {
	it("exposes usableSendBudget after a paid handshake", async () => {
		await withClient(
			() =>
				TightbeamWsClient.connectMutual(
					muxMutualEndpoint,
					certBytes("server.cert.der"),
					certBytes("client.cert.der"),
					certBytes("client.key"),
					mutualSessionOptions(),
				),
			async (client) => {
				expect(client.usableSendBudget).toBeTypeOf("number");
				expect(client.usableSendBudget).toBeGreaterThan(0);
				expect(client.sessionReceiptDer).toBeInstanceOf(Uint8Array);
			},
		);
	});

	it("closes the session when settlement is unpaid", async () => {
		// The client finishes dial before the server settles the
		// countersigned receipt. An unpaid challenge still aborts the
		// server side; the client observes that as `closed`.
		const client = await TightbeamWsClient.connectMutual(
			muxMutualEndpoint,
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

	it("pays and emits under session budgets", async () => {
		await withClient(
			() =>
				TightbeamWsClient.connectMutual(
					muxMutualEndpoint,
					certBytes("server.cert.der"),
					certBytes("client.cert.der"),
					certBytes("client.key"),
					mutualSessionOptions(),
				),
			async (client) => {
				const built = await frame(new Uint8Array([0xb0, 0xee]))
					.withId("paywall-emit")
					.withOrder(1)
					.build();
				const response = await emitOrFail(client, built);
				expect(response.id).toEqual(built.id);
			},
		);
	});

	it("openStream multi-push works under the paywall", async () => {
		await withClient(
			() =>
				TightbeamWsClient.connectMutual(
					muxMutualEndpoint,
					certBytes("server.cert.der"),
					certBytes("client.cert.der"),
					certBytes("client.key"),
					mutualSessionOptions(),
				),
			async (client) => {
				const built = await frame(new Uint8Array([0xb0, 0x51]))
					.withId("paywall-stream")
					.withOrder(1)
					.build();

				const der = built.toDer();
				const mid = Math.floor(der.length / 2);

				const stream = client.openStream();
				await stream.push(der.subarray(0, mid));
				await stream.push(der.subarray(mid));

				const response = await stream.close();
				expect(response).toBeDefined();
			},
		);
	});
});
