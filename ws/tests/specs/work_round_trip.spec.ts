import type { WorkRefusalResult, WorkRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { Identities } from "../env.js";
import { STACK } from "../stack.js";
import { openApp } from "./helpers.js";

/**
 * A servlet type that no hive serves.
 */
const UNSERVED = `${STACK.workServlet}-unserved`;

test("submits a signed work frame and verifies the served response frame", async ({ page }) => {
	await openApp(page);

	const result: WorkRoundTripResult = await page.evaluate((options) => window.tb.workRoundTrip(options), {
		url: STACK.workGatewayEndpoint,
		serverCertB64: Identities.stack.base64("server.cert.der"),
		target: STACK.workServlet,
		payloadHex: "cafef00d",
		idText: "e2e-work-1",
		order: 7,
		workKeyB64: Identities.stack.base64("client.key"),
	});
	expect(result.bodyText).toBe("pong:cafef00d:true");
	expect(result.idText).toBe("e2e-work-1");
	expect(result.signatureValid).toBe(true);
});

test("refuses work for an unserved servlet type with a typed status", async ({ page }) => {
	await openApp(page);

	const result: WorkRefusalResult = await page.evaluate((options) => window.tb.workRefusal(options), {
		url: STACK.workGatewayEndpoint,
		serverCertB64: Identities.stack.base64("server.cert.der"),
		target: UNSERVED,
		payloadHex: "0badf00d",
		workKeyB64: Identities.stack.base64("client.key"),
	});
	expect(result.rejectionName).toBe("TightbeamTransportError");
	expect(result.rejectionCode).toBe("WorkRefused");
	expect(result.rejectionStatus).toBe("Unavailable");
});
