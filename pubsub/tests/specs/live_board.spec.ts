/**
 * Liveness proof against the real dockerized tightbeam node: one page
 * publishes, another page's DOM updates through the registry fan-out,
 * with no polling and no reload.
 *
 *   browser (publisher page)
 *      | HPKE ws: pub/<topic> [inner frame: signed + sealed note]
 *      v
 *   pubsub-demo ............... TopicRegistry (default Local backplane)
 *      | server push (wrapper order 1, inner relayed byte-for-byte)
 *      v
 *   browser (subscriber page) . verifies signature, unseals, renders
 */

import { expect, test } from "@playwright/test";

import { TopicRun } from "../fixtures.js";
import { STACK } from "../node/stack.js";

test("sealed signed publishes render live on another page", async ({ browser }) => {
	const topic = TopicRun.current.topic("board");
	const board = STACK.boardPath({ endpoint: STACK.pubsubEndpoint, topic, mode: "sealed" });
	const context = await browser.newContext();

	/*
	 * Two pages, two encrypted WebSocket connections, one topic.
	 */
	const subscriber = await context.newPage();
	await subscriber.goto(board);
	await expect(subscriber.locator("#status")).toHaveText("subscribed");

	const publisher = await context.newPage();
	await publisher.goto(board);
	await expect(publisher.locator("#status")).toHaveText("subscribed");

	for (const payload of ["hello", "again"]) {
		await publisher.fill("#payload", payload);
		await publisher.click("#publish");
	}

	await expect(publisher.locator("#published")).toHaveText("2");

	/*
	 * Each delivered inner frame still carries the publisher's signature and
	 * seal, which the page verified and opened: both survived the registry
	 * relay end to end.
	 */
	const items = subscriber.locator("#board li");
	await expect(items).toHaveText(["hello", "again"]);
	await expect(items.nth(0)).toHaveAttribute("data-order", "1");
	await expect(items.nth(1)).toHaveAttribute("data-order", "2");
	for (const index of [0, 1]) {
		await expect(items.nth(index)).toHaveAttribute("data-signed", "true");
		await expect(items.nth(index)).toHaveAttribute("data-sealed", "true");
	}

	/*
	 * The publisher subscribes too: its own publishes come back to it.
	 */
	await expect(publisher.locator("#board li")).toHaveText(["hello", "again"]);

	await context.close();
});
