import type { RoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { Identities } from "../env.js";
import { STACK } from "../stack.js";
import { openApp } from "./helpers.js";

const serverCert = Identities.stack.base64("server.cert.der");
const clientCert = Identities.stack.base64("client.cert.der");
const clientKey = Identities.stack.base64("client.key");

interface SecureCase {
	readonly name: string;
	readonly payloadHex: string;
	readonly id: string;
	readonly order: number;
}

const cases: readonly SecureCase[] = [
	{
		name: "small payload",
		payloadHex: "deadbeefcafe0123",
		id: "e2e-secure",
		order: 1,
	},
	{
		name: "longer payload",
		payloadHex: "ff00ff00ff7f80aa55",
		id: "secure-meta",
		order: 99,
	},
];

for (const testCase of cases) {
	test(`round-trips over an HPKE-encrypted session: ${testCase.name}`, async ({ page }) => {
		await openApp(page);

		const result: RoundTripResult = await page.evaluate((echo) => window.tb.secureRoundTrip(echo), {
			url: STACK.muxEndpoint,
			serverCertB64: serverCert,
			payloadHex: testCase.payloadHex,
			idText: testCase.id,
			order: testCase.order,
		});
		expect(result.bodyHex).toBe(testCase.payloadHex);
		expect(result.idText).toBe(testCase.id);
		expect(result.order).toBe(String(testCase.order));
		expect(result.version).toBe(0);
	});
}

test("round-trips over a mutually-authenticated encrypted session", async ({ page }) => {
	await openApp(page);

	const result: RoundTripResult = await page.evaluate((echo) => window.tb.mutualRoundTrip(echo), {
		url: STACK.muxMutualEndpoint,
		serverCertB64: serverCert,
		clientCertB64: clientCert,
		clientKeyB64: clientKey,
		payloadHex: "0badc0de",
		idText: "e2e-mutual",
		order: 7,
	});
	expect(result.bodyHex).toBe("0badc0de");
	expect(result.idText).toBe("e2e-mutual");
	expect(result.order).toBe("7");
});

test("authenticates mutually through an external signer in the browser", async ({ page }) => {
	await openApp(page);

	const result: RoundTripResult = await page.evaluate((echo) => window.tb.mutualSignerRoundTrip(echo), {
		url: STACK.muxMutualEndpoint,
		serverCertB64: serverCert,
		clientCertB64: clientCert,
		clientKeyB64: clientKey,
		payloadHex: "0badc1de",
		idText: "e2e-mutual-signer",
		order: 8,
	});
	expect(result.bodyHex).toBe("0badc1de");
	expect(result.idText).toBe("e2e-mutual-signer");
});
