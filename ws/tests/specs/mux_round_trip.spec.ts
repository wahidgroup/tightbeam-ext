import type {
	MuxCallbackResult,
	MuxConcurrentResult,
	MuxDrainResult,
	MuxLifecycleResult,
	MuxRefusalResult,
} from "../app/main.js";
import { expect, test } from "@playwright/test";

import { certBase64, muxClearEndpoint, muxEndpoint } from "../env.js";
import { openApp } from "./helpers.js";

const serverCert = certBase64("server.cert.der");

const PAYLOAD_HEX = "deadbeef";
const REPLY_HEX = "ca11bac4";

test("correlates concurrent browser emits by stream", async ({ page }) => {
	await openApp(page);

	const result: MuxConcurrentResult = await page.evaluate(
		({ url, cert, payload }) =>
			window.tbMuxConcurrentRoundTrip(url, cert, payload),
		{ url: muxEndpoint, cert: serverCert, payload: PAYLOAD_HEX },
	);
	expect(result.echoedIds).toEqual([
		"mux-browser-1",
		"mux-browser-2",
		"mux-browser-3",
	]);
	expect(result.echoedBodiesHex).toEqual([
		`${PAYLOAD_HEX}00`,
		`${PAYLOAD_HEX}01`,
		`${PAYLOAD_HEX}02`,
	]);
});

test("answers a server-initiated stream from the page handler", async ({
	page,
}) => {
	await openApp(page);

	const result: MuxCallbackResult = await page.evaluate(
		({ url, cert, payload, reply }) =>
			window.tbMuxCallbackRoundTrip(url, cert, payload, reply),
		{
			url: muxEndpoint,
			cert: serverCert,
			payload: PAYLOAD_HEX,
			reply: REPLY_HEX,
		},
	);
	expect(result.servedIds).toEqual(["call-me-browser"]);
	expect(result.relayedIdText).toBe("browser-reply");
	expect(result.relayedBodyHex).toBe(REPLY_HEX);
});

test("probes the mux lifecycle surface from the browser", async ({ page }) => {
	await openApp(page);

	const result: MuxLifecycleResult = await page.evaluate(
		({ url, cert }) => window.tbMuxLifecycleProbe(url, cert),
		{ url: muxEndpoint, cert: serverCert },
	);
	expect(result).toEqual({
		headroom: true,
		pendingIdle: true,
		liveReasonEmpty: true,
		abandonedPingRejection: "ping abandoned",
		drainCode: "Draining",
		localReasonEmpty: true,
	});
});

test("surfaces the peer's goaway reason in the browser", async ({ page }) => {
	await openApp(page);

	const result: MuxDrainResult = await page.evaluate(
		({ url, cert }) => window.tbMuxDrainReason(url, cert),
		{ url: muxEndpoint, cert: serverCert },
	);
	expect(result).toEqual({
		reason: "EnhanceYourCalm",
		code: 2,
		emitRejection: "drain observed",
	});
});

test("relays a StreamRefusal code from the page handler to the caller", async ({
	page,
}) => {
	await openApp(page);

	const result: MuxRefusalResult = await page.evaluate(
		({ url, cert, payload }) =>
			window.tbMuxRefusalRoundTrip(url, cert, payload),
		{ url: muxEndpoint, cert: serverCert, payload: PAYLOAD_HEX },
	);
	expect(result).toEqual({
		rejectionName: "TightbeamTransportError",
		rejectionCode: "NotFound",
	});
});

test("parks a server-initiated stream until the page handler registers", async ({
	page,
}) => {
	await openApp(page);

	const result: MuxCallbackResult = await page.evaluate(
		({ url, cert, payload, reply }) =>
			window.tbMuxParkedCallbackRoundTrip(url, cert, payload, reply),
		{
			url: muxEndpoint,
			cert: serverCert,
			payload: PAYLOAD_HEX,
			reply: REPLY_HEX,
		},
	);
	expect(result.servedIds).toEqual(["call-me-parked-browser"]);
	expect(result.relayedIdText).toBe("late-browser-reply");
	expect(result.relayedBodyHex).toBe(REPLY_HEX);
});

test("correlates concurrent cleartext browser emits by stream", async ({
	page,
}) => {
	await openApp(page);

	const result: MuxConcurrentResult = await page.evaluate(
		({ url, payload }) =>
			window.tbMuxClearConcurrentRoundTrip(url, payload),
		{ url: muxClearEndpoint, payload: PAYLOAD_HEX },
	);
	expect(result.echoedIds).toEqual([
		"mux-browser-1",
		"mux-browser-2",
		"mux-browser-3",
	]);
	expect(result.echoedBodiesHex).toEqual([
		`${PAYLOAD_HEX}00`,
		`${PAYLOAD_HEX}01`,
		`${PAYLOAD_HEX}02`,
	]);
});
