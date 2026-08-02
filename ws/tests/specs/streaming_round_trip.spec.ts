import { expect, test } from "@playwright/test";

import type { RoundTripResult } from "../app/main.js";
import { certBase64, muxEndpoint } from "../env.js";
import { openApp } from "./helpers.js";

const serverCert = certBase64("server.cert.der");

test("openStream multi-push round-trip in the browser", async ({ page }) => {
	await openApp(page);

	const result: RoundTripResult = await page.evaluate(
		({ url, cert }) =>
			window.tbStreamingRoundTrip(url, cert, "a1b2c3", "e2e-stream"),
		{ url: muxEndpoint, cert: serverCert },
	);
	expect(result.bodyHex).toBe("a1b2c3");
	// Progressive echo stamps the Open route (`routed:<target>:<hops>`).
	expect(result.idText).toBe("routed::255");
});
