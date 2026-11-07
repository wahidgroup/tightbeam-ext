import { describe, expect, it } from "vitest";

import type { Frame } from "@wahidgroup/tightbeam-ws-client";
import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";

import { certBytes } from "../env.js";
import { withClient } from "../fixtures.js";
import { STACK } from "../stack.js";

/**
 * Work submissions against the real work gateway of the stack: a gateway, a
 * hive, and the `work-probe` servlet, which answers `pong:<hex>:<verified>`.
 */

const ENGINE = await TightbeamWsClient.init();

const TEXT = new TextDecoder();

/**
 * The servlet type the work-gateway container registers at startup.
 */
const SERVED_TARGET = "urn:tightbeam::servlet:work-probe";

/**
 * A servlet type no hive serves, so the gateway refuses it.
 */
const UNSERVED_TARGET = "urn:tightbeam::servlet:unserved";

/**
 * The end-to-end work signing key, which the servlet verifies.
 */
const WORK_KEY = ENGINE.signingKey(certBytes("client.key"));

/**
 * The payload of every work frame in this suite.
 */
const PAYLOAD = new Uint8Array([0xca, 0xfe, 0xf0, 0x0d]);

/**
 * The reason of every abort in this suite.
 */
const GAVE_UP = new Error("the caller gave up");

/**
 * Dial the work gateway, pinning the server certificate of the stack.
 */
function connectGateway(): Promise<TightbeamWsClient> {
	const serverCertDer = certBytes("server.cert.der");
	const dialing = ENGINE.connect(STACK.workGatewayEndpoint, serverCertDer);
	return dialing;
}

/**
 * A signed work frame under the id `idText`.
 */
async function workFrame(idText: string): Promise<Frame> {
	const built = await ENGINE.frameBuilder(PAYLOAD)
		.withId(idText)
		.withOrder(7)
		.withSigner(WORK_KEY)
		.build();
	return built;
}

describe("submitWork against the work gateway", () => {
	it("a served target answers the servlet reply for the payload", async () => {
		const work = await workFrame("node-work-served");

		const reply = await withClient(connectGateway, (client) =>
			client.submitWork(SERVED_TARGET, work),
		);

		expect(TEXT.decode(reply.message(ENGINE.opaque))).toBe(
			"pong:cafef00d:true",
		);
		expect(TEXT.decode(reply.id)).toBe("node-work-served");
	});

	it("an abort rejects the submission with its reason", async () => {
		const work = await workFrame("node-work-aborted");
		const controller = new AbortController();

		const submitted = withClient(connectGateway, (client) => {
			const submission = client.submitWork(SERVED_TARGET, work, {
				signal: controller.signal,
			});
			controller.abort(GAVE_UP);
			return submission;
		});

		await expect(submitted).rejects.toBe(GAVE_UP);
	});

	it("an unserved target is WorkRefused with status Unavailable", async () => {
		const work = await workFrame("node-work-unserved");
		const refused = withClient(connectGateway, (client) =>
			client.submitWork(UNSERVED_TARGET, work),
		);

		await expect(refused).rejects.toMatchObject({
			code: "WorkRefused",
			status: "Unavailable",
		});
	});

	it("a closed client refuses with ConnectionClosed", async () => {
		const work = await workFrame("node-work-closed");
		const client = await connectGateway();
		await client.close();

		const refused = client.submitWork(SERVED_TARGET, work);

		await expect(refused).rejects.toMatchObject({
			code: "ConnectionClosed",
		});
	});
});
