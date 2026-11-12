import { expect, test } from "@playwright/test";

import type { RoundTripResult } from "../app/main.js";
import { Identities } from "../env.js";
import { EchoedRoute } from "../fixtures.js";
import { STACK } from "../stack.js";
import { openApp } from "./helpers.js";

const serverCert = Identities.stack.base64("server.cert.der");

test("openStream multi-push round-trip in the browser", async ({ page }) => {
	await openApp(page);

	const result: RoundTripResult = await page.evaluate((options) => window.tb.streamingRoundTrip(options), {
		url: STACK.muxEndpoint,
		serverCertB64: serverCert,
		payloadHex: "a1b2c3",
		idText: "e2e-stream",
	});
	expect(result.bodyHex).toBe("a1b2c3");
	// The progressive echo stamps the route of the Open on the id.
	expect(EchoedRoute.of(result.idText).target).toBeUndefined();
});
