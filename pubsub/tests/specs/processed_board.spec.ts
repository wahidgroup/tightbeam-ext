/**
 * Custom-backplane proof: this demo server's `RelayBackplane` detours
 * every publish through a backend-only servlet before fan-out, so the
 * boards render the transformed note instead of the published one.
 * Every hop is ECIES encrypted. The published note travels signed but
 * unsealed: the servlet must read and rewrite the body, so mid-stream
 * transformation and an end-to-end seal are mutually exclusive, and the
 * rebuilt frame arrives unverified by design. The servlet seals its
 * rebuild under the pre-shared topic key, so the transformed note
 * arrives encrypted and the subscriber's envelope opens it.
 *
 *   browser (publisher page)
 *      | ECIES ws: pub/<topic> [inner frame: signed note "hello"]
 *      v
 *   pubsub-demo-processed ........ TopicRegistry + RelayBackplane
 *      | ECIES tightbeam ws mux request [inner frame]
 *      v
 *   pubsub-processor ............. backend-only servlet: lifts the
 *      |                           note, uppercases its text, rebuilds
 *      | answer [unsigned sealed inner frame: "HELLO"]
 *      v
 *   RelayBackplane ............... sequences via Local, fans out
 *      | server push (wrapper order 1)
 *      v
 *   browser (subscriber page) .... unseals "HELLO", unverified badge
 */

import { expect, test } from "@playwright/test";

import { certBase64, pubsubProcessedEndpoint } from "../node/env.js";

/**
 * The demo server's registry is shared by every connection of the whole
 * suite run, so each test isolates itself on its own topic.
 */
const RUN = Math.random().toString(36).slice(2, 10);

function boardUrl(topic: string): string {
	const params = new URLSearchParams({
		endpoint: pubsubProcessedEndpoint,
		topic,
		cert: certBase64("server.cert.der"),
		processed: "1",
	});
	return `/?${params.toString()}`;
}

test("publishes come back transformed by the backend servlet", async ({
	browser,
}) => {
	const topic = `e2e/${RUN}/processed`;
	const context = await browser.newContext();

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
	 * Uppercase in the DOM is the proof the note crossed the servlet;
	 * the unverified badge is the proof the servlet rebuilt the frame;
	 * the sealed badge is the proof its rebuild arrived encrypted and
	 * the subscriber's envelope opened it.
	 */
	const items = subscriber.locator("#board li");
	await expect(items).toHaveText(["HELLO", "AGAIN"]);
	await expect(items.nth(0)).toHaveAttribute("data-order", "1");
	await expect(items.nth(1)).toHaveAttribute("data-order", "2");
	for (const index of [0, 1]) {
		await expect(items.nth(index)).toHaveAttribute(
			"data-verified",
			"false",
		);
		await expect(items.nth(index)).toHaveAttribute("data-sealed", "true");
	}

	await context.close();
});
