import { describe, expect, it } from "vitest";

import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";

import { demoIdentity } from "../env.js";
import { emitOrFail, mutualSessionOptions, withClient } from "../fixtures.js";
import { STACK } from "../stack.js";

const ENGINE = await TightbeamWsClient.init();

describe("Node mutual paywall", () => {
	it("exposes usableSendBudget after a paid handshake", async () => {
		await withClient(
			() =>
				ENGINE.connectMutual(
					STACK.muxMutualEndpoint,
					demoIdentity(),
					mutualSessionOptions(STACK.paywall),
				),
			async (client) => {
				expect(client.usableSendBudget).toBeTypeOf("number");
				expect(client.usableSendBudget).toBeGreaterThan(0);
				expect(client.sessionReceiptDer).toBeInstanceOf(Uint8Array);
			},
		);
	});

	it("closes the session when settlement is unpaid", async () => {
		/*
		 * The client finishes dial before the server settles the
		 * countersigned receipt. An unpaid challenge still aborts the
		 * server side. The client observes that as `closed`.
		 */
		const client = await ENGINE.connectMutual(
			STACK.muxMutualEndpoint,
			demoIdentity(),
			mutualSessionOptions(STACK.paywall, 0),
		);

		await expect(client.closed).resolves.toBeTruthy();
	});

	it("pays and emits under session budgets", async () => {
		await withClient(
			() =>
				ENGINE.connectMutual(
					STACK.muxMutualEndpoint,
					demoIdentity(),
					mutualSessionOptions(STACK.paywall),
				),
			async (client) => {
				const built = await ENGINE.frameBuilder(
					new Uint8Array([0xb0, 0xee]),
				)
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
				ENGINE.connectMutual(
					STACK.muxMutualEndpoint,
					demoIdentity(),
					mutualSessionOptions(STACK.paywall),
				),
			async (client) => {
				const built = await ENGINE.frameBuilder(
					new Uint8Array([0xb0, 0x51]),
				)
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
