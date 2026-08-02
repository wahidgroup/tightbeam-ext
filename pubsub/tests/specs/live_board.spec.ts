/**
 * Liveness proof against the real dockerized tightbeam node: one page
 * publishes, another page's DOM updates through the registry fan-out,
 * with no polling and no reload. Every hop is ECIES encrypted, and every
 * message is a full tightbeam frame (the `Framed` codec): a typed JSON
 * note, signed by the publisher, sealed under the topic's AES-256-GCM
 * key. The wrapper only stamps topic and sequence; the broker never
 * reads the note.
 *
 *   browser (publisher page)
 *      | ECIES ws: pub/<topic> [inner frame: signed + sealed note]
 *      v
 *   pubsub-demo ............... TopicRegistry (default Local backplane)
 *      | server push (wrapper order 1, inner relayed byte-for-byte)
 *      v
 *   browser (subscriber page) . verifies signature, unseals, renders
 */

import { expect, test } from "@playwright/test";

import { certBase64, pubsubEndpoint } from "../node/env.js";

/**
 * The demo server's registry is shared by every connection of the whole
 * suite run, so each test isolates itself on its own topic.
 */
const RUN = Math.random().toString(36).slice(2, 10);

function boardUrl(topic: string): string {
	const params = new URLSearchParams({
		endpoint: pubsubEndpoint,
		topic,
		cert: certBase64("server.cert.der"),
		clientCert: certBase64("client.cert.der"),
		clientKey: certBase64("client.key"),
		seal: "1",
	});
	return `/?${params.toString()}`;
}

test("sealed signed publishes render live on another page", async ({
	browser,
}) => {
	const topic = `e2e/${RUN}/board`;
	const context = await browser.newContext();

	/*
	 * Two pages, two encrypted WebSocket connections, one topic.
	 */
	const subscriber = await context.newPage();
	await subscriber.goto(boardUrl(topic));
	await expect(subscriber.locator("#status")).toHaveText("subscribed");

	const publisher = await context.newPage();
	await publisher.goto(boardUrl(topic));
	await expect(publisher.locator("#status")).toHaveText("subscribed");

	for (const payload of ["hello", "again"]) {
		await publisher.fill("#payload", payload);
		await publisher.click("#publish");
	}

	await expect(publisher.locator("#published")).toHaveText("2");

	/*
	 * The notes arrive unsealed and verified: the publisher's signature
	 * and seal survived the registry relay end to end.
	 */
	const items = subscriber.locator("#board li");
	await expect(items).toHaveText(["hello", "again"]);
	await expect(items.nth(0)).toHaveAttribute("data-order", "1");
	await expect(items.nth(1)).toHaveAttribute("data-order", "2");
	for (const index of [0, 1]) {
		await expect(items.nth(index)).toHaveAttribute("data-verified", "true");
		await expect(items.nth(index)).toHaveAttribute("data-sealed", "true");
	}

	/*
	 * The publisher subscribes too: its own publishes come back to it.
	 */
	await expect(publisher.locator("#board li")).toHaveText(["hello", "again"]);

	await context.close();
});
