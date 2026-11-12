/**
 * Pubsub demo compose always enables the session-budget paywall.
 * These cases prove settlement failure and a paid dial on that stack.
 */

import { describe, expect, it } from "vitest";

import { Engine } from "@wahidgroup/tightbeam-ws-client";
import { ClientPorts, SubscriptionManager } from "@wahidgroup/tightbeam-pubsub-client";

import { Identities } from "#ws-env";
import { NobleTransportSigner } from "#ws-signer";
import { TopicRun } from "../fixtures.js";
import { STACK } from "./stack.js";

const ENGINE = await Engine.load();

describe("pubsub mutual paywall", () => {
	it("exposes usableSendBudget after a paid handshake", async () => {
		await using client = await ENGINE.connectMutual(
			STACK.pubsubEndpoint,
			Identities.stack.demo(),
			STACK.dial.paywall.sessionOptions(),
		);
		expect(client.usableSendBudget).toBeTypeOf("number");
		expect(client.usableSendBudget).toBeGreaterThan(0);
	});

	it("closes the session when settlement is unpaid", async () => {
		const client = await ENGINE.connectMutual(
			STACK.pubsubEndpoint,
			Identities.stack.demo(),
			STACK.dial.paywall.sessionOptions(0),
		);

		await expect(client.closed).resolves.toBeTruthy();
	});

	/*
	 * The server pins the demo client certificate, so a handshake that
	 * completes proves the external signer signed with the certificate key,
	 * and the delivered update proves the paid session carries traffic.
	 */
	it("completes a paid round trip with the client key in an external signer", async () => {
		const signer = new NobleTransportSigner(ENGINE, Identities.stack.bytes("client.key"));

		await using client = await ENGINE.connectMutual(
			STACK.pubsubEndpoint,
			Identities.stack.demo(signer),
			STACK.dial.paywall.sessionOptions(),
		);
		const ports = ClientPorts.split(client);
		const manager = new SubscriptionManager(ports);
		const topic = TopicRun.current.topic("signer");
		const subscription = await manager.subscribe(topic, {
			codec: ENGINE.opaque,
		});

		const updates = subscription[Symbol.asyncIterator]();
		const sent = new TextEncoder().encode("ok");
		await manager.publish(topic, sent, { codec: ENGINE.opaque });

		const next = await updates.next();
		expect(next.done).toBe(false);
		expect(next.value?.message).toEqual(sent);

		await subscription.unsubscribe();
	});
});
