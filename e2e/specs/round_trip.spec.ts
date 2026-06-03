import { expect, test } from "@playwright/test";

import type { RoundTripResult } from "../app/main.js";

let wsEndpoint = "ws://localhost:9100";
if (process.env.E2E_ECHO_WS_ENDPOINT) {
	wsEndpoint = process.env.E2E_ECHO_WS_ENDPOINT;
}

interface RoundTripCase {
	readonly name: string;
	readonly payloadHex: string;
	readonly id: string;
	readonly order: number;
}

const cases: readonly RoundTripCase[] = [
	{
		name: "small payload",
		payloadHex: "deadbeefcafe0123",
		id: "e2e",
		order: 0,
	},
	{ name: "single byte", payloadHex: "00", id: "alpha", order: 7 },
	{
		name: "longer payload with metadata",
		payloadHex: "ff00ff00ff7f80",
		id: "frame-meta",
		order: 42,
	},
];

for (const testCase of cases) {
	test(`round-trips a built frame through the echo server: ${testCase.name}`, async ({
		page,
	}) => {
		await page.goto("/");
		await expect(page.locator("#status")).toHaveText("client ready");

		const result: RoundTripResult = await page.evaluate(
			({ url, payload, id, order }) =>
				window.tbRoundTrip(url, payload, id, order),
			{
				url: wsEndpoint,
				payload: testCase.payloadHex,
				id: testCase.id,
				order: testCase.order,
			},
		);

		expect(result.bodyHex).toBe(testCase.payloadHex);
		expect(result.idText).toBe(testCase.id);
		expect(result.order).toBe(String(testCase.order));
		expect(result.version).toBe(0);
		expect(result.signed).toBe(false);
		expect(result.messageIntegrity).toBe(false);
		expect(result.frameIntegrity).toBe(false);
	});
}
