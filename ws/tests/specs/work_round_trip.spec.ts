import type { WorkRefusalResult, WorkRoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { certBase64, workGatewayEndpoint } from "../env.js";
import { openApp } from "./helpers.js";

/**
 * The servlet type the work-gateway container registers at startup.
 */
const SERVED_TARGET = "urn:tightbeam::servlet:work-probe";

/**
 * A servlet type no hive serves, so the gateway refuses it.
 */
const UNSERVED_TARGET = "urn:tightbeam::servlet:unserved";

test("submits a signed work frame and verifies the served response frame", async ({
	page,
}) => {
	await openApp(page);

	const result: WorkRoundTripResult = await page.evaluate(
		(options) => window.tbWorkRoundTrip(options),
		{
			url: workGatewayEndpoint,
			serverCertB64: certBase64("server.cert.der"),
			target: SERVED_TARGET,
			payloadHex: "cafef00d",
			idText: "e2e-work-1",
			order: 7,
			workKeyB64: certBase64("client.key"),
		},
	);

	expect(result.bodyText).toBe("pong:cafef00d:true");
	expect(result.idText).toBe("e2e-work-1");
	expect(result.signatureValid).toBe(true);
});

test("refuses work for an unserved servlet type with a typed status", async ({
	page,
}) => {
	await openApp(page);

	const result: WorkRefusalResult = await page.evaluate(
		({ url, serverCert, workKey, target }) =>
			window.tbWorkRefusal(url, serverCert, target, "0badf00d", workKey),
		{
			url: workGatewayEndpoint,
			serverCert: certBase64("server.cert.der"),
			workKey: certBase64("client.key"),
			target: UNSERVED_TARGET,
		},
	);

	expect(result.rejectionName).toBe("TightbeamTransportError");
	expect(result.rejectionCode).toBe("WorkRefused");
	expect(result.rejectionStatus).toBe("Unavailable");
});
