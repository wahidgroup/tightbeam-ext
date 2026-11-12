import { describe, expect, it } from "vitest";

import type { Frame, TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";
import { Engine } from "@wahidgroup/tightbeam-ws-client";

import { Identities } from "../env.js";
import { STACK } from "../stack.js";

/**
 * Work submissions against the real work gateway of the stack: a gateway, a
 * hive, and the probe servlet, which answers `pong:<hex>:<verified>`.
 */

const ENGINE = await Engine.load();

const TEXT = new TextDecoder();

/**
 * The end-to-end work signing key, which the servlet verifies.
 */
const WORK_KEY = ENGINE.signingKey(Identities.stack.bytes("client.key"));

/**
 * A servlet type that no hive serves.
 */
const UNSERVED = `${STACK.workServlet}-unserved`;

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
	const dialing = ENGINE.connect(STACK.workGatewayEndpoint, STACK.serverCertDer);
	return dialing;
}

/**
 * A signed work frame under the id `idText`.
 */
async function workFrame(idText: string): Promise<Frame> {
	const built = await ENGINE.frameBuilder(PAYLOAD).withId(idText).withOrder(7).withSigner(WORK_KEY).build();
	return built;
}

describe("submitWork against the work gateway", () => {
	it("a served target answers the servlet reply for the payload", async () => {
		const work = await workFrame("node-work-served");
		await using client = await connectGateway();
		const reply = await client.submitWork(STACK.workServlet, work);
		expect(TEXT.decode(await reply.open(ENGINE.opaque))).toBe("pong:cafef00d:true");
		expect(TEXT.decode(reply.id)).toBe("node-work-served");
	});

	it("an abort rejects the submission with its reason", async () => {
		const work = await workFrame("node-work-aborted");
		const controller = new AbortController();
		await using client = await connectGateway();
		const submitted = client.submitWork(STACK.workServlet, work, {
			signal: controller.signal,
		});
		controller.abort(GAVE_UP);

		await expect(submitted).rejects.toBe(GAVE_UP);
	});

	it("an unserved target is WorkRefused with status Unavailable", async () => {
		const work = await workFrame("node-work-unserved");
		await using client = await connectGateway();
		const refused = client.submitWork(UNSERVED, work);

		await expect(refused).rejects.toMatchObject({
			code: "WorkRefused",
			status: "Unavailable",
		});
	});

	it("a closed client refuses with ConnectionClosed", async () => {
		const work = await workFrame("node-work-closed");
		const client = await connectGateway();
		await client.close();

		const refused = client.submitWork(STACK.workServlet, work);
		await expect(refused).rejects.toMatchObject({
			code: "ConnectionClosed",
		});
	});
});
