/**
 * Custom-backplane proof: this demo server's `RelayBackplane` detours
 * every publish through a backend-only servlet before fan-out, so the
 * boards render the transformed note instead of the published one.
 *
 *   browser (publisher page)
 *      | HPKE ws: pub/<topic> [inner frame: signed note "hello"]
 *      v
 *   pubsub-demo-processed ........ TopicRegistry + RelayBackplane
 *      | HPKE tightbeam ws mux request [inner frame]
 *      v
 *   pubsub-processor ............. backend-only servlet: lifts the
 *      |                           note, uppercases its text, rebuilds
 *      | answer [unsigned sealed inner frame: "HELLO"]
 *      v
 *   RelayBackplane ............... sequences via Local, fans out
 *      | server push (wrapper order 1)
 *      v
 *   browser (subscriber page) .... unseals "HELLO" from an unsigned frame
 */

import { expect, test } from "@playwright/test";

import { TopicRun } from "../fixtures.js";
import { STACK } from "../node/stack.js";

test("publishes come back transformed by the backend servlet", async ({ browser }) => {
	const topic = TopicRun.current.topic("processed");
	const endpoint = STACK.pubsubProcessedEndpoint;
	const board = STACK.boardPath({ endpoint, topic, mode: "processed" });
	const context = await browser.newContext();

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
	 * Uppercase in the DOM is the proof the note crossed the servlet. The
	 * publisher signed each note, so an inner frame that arrives without a
	 * signature is the proof the servlet rebuilt the frame, and a sealed one
	 * the proof its rebuild arrived encrypted and the page opened it.
	 */
	const items = subscriber.locator("#board li");
	await expect(items).toHaveText(["HELLO", "AGAIN"]);
	await expect(items.nth(0)).toHaveAttribute("data-order", "1");
	await expect(items.nth(1)).toHaveAttribute("data-order", "2");
	for (const index of [0, 1]) {
		await expect(items.nth(index)).toHaveAttribute("data-signed", "false");
		await expect(items.nth(index)).toHaveAttribute("data-sealed", "true");
	}

	await context.close();
});
