import type { RoundTripResult } from "../app/main.js";
import { expect, test } from "@playwright/test";

import { certBase64, mutualEndpoint, secureEndpoint } from "../env.js";
import { openApp } from "./helpers.js";

const serverCert = certBase64("server.cert.der");
const clientCert = certBase64("client.cert.der");
const clientKey = certBase64("client.key");

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
	test(`round-trips over an ECIES-encrypted session: ${testCase.name}`, async ({
		page,
	}) => {
		await openApp(page);

		const result: RoundTripResult = await page.evaluate(
			({ url, cert, payload, id, order }) =>
				window.tbSecureRoundTrip(url, cert, payload, id, order),
			{
				url: secureEndpoint,
				cert: serverCert,
				payload: testCase.payloadHex,
				id: testCase.id,
				order: testCase.order,
			},
		);
		expect(result.bodyHex).toBe(testCase.payloadHex);
		expect(result.idText).toBe(testCase.id);
		expect(result.order).toBe(String(testCase.order));
		expect(result.version).toBe(0);
	});
}

test("round-trips over a mutually-authenticated encrypted session", async ({
	page,
}) => {
	await openApp(page);

	const result: RoundTripResult = await page.evaluate(
		({ url, cert, clientCertB64, clientKeyB64 }) =>
			window.tbMutualRoundTrip(
				url,
				cert,
				clientCertB64,
				clientKeyB64,
				"0badc0de",
				"e2e-mutual",
				7,
			),
		{
			url: mutualEndpoint,
			cert: serverCert,
			clientCertB64: clientCert,
			clientKeyB64: clientKey,
		},
	);
	expect(result.bodyHex).toBe("0badc0de");
	expect(result.idText).toBe("e2e-mutual");
	expect(result.order).toBe("7");
});
