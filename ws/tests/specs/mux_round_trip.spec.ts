import { expect, test } from "@playwright/test";

import type {
	MuxCallbackResult,
	MuxConcurrentResult,
	MuxDrainResult,
	MuxLifecycleResult,
	MuxRefusalResult,
} from "../app/main.js";
import { Identities } from "../env.js";
import { STACK } from "../stack.js";
import { openApp } from "./helpers.js";

const serverCert = Identities.stack.base64("server.cert.der");

const PAYLOAD_HEX = "deadbeef";
const REPLY_HEX = "ca11bac4";

test("correlates concurrent browser emits by stream", async ({ page }) => {
	await openApp(page);

	const result: MuxConcurrentResult = await page.evaluate((options) => window.tb.muxConcurrentRoundTrip(options), {
		url: STACK.muxEndpoint,
		serverCertB64: serverCert,
		payloadHex: PAYLOAD_HEX,
	});
	expect(result.echoedIds).toEqual(["mux-browser-1", "mux-browser-2", "mux-browser-3"]);
	expect(result.echoedBodiesHex).toEqual([`${PAYLOAD_HEX}00`, `${PAYLOAD_HEX}01`, `${PAYLOAD_HEX}02`]);
});

test("answers a server-initiated stream from the page handler", async ({ page }) => {
	await openApp(page);

	const result: MuxCallbackResult = await page.evaluate((options) => window.tb.muxCallbackRoundTrip(options), {
		url: STACK.muxEndpoint,
		serverCertB64: serverCert,
		payloadHex: PAYLOAD_HEX,
		replyHex: REPLY_HEX,
	});
	expect(result.servedIds).toEqual(["call-me-browser"]);
	expect(result.relayedIdText).toBe("browser-reply");
	expect(result.relayedBodyHex).toBe(REPLY_HEX);
});

test("probes the mux lifecycle surface from the browser", async ({ page }) => {
	await openApp(page);

	const result: MuxLifecycleResult = await page.evaluate((options) => window.tb.muxLifecycleProbe(options), {
		url: STACK.muxEndpoint,
		serverCertB64: serverCert,
	});
	expect(result).toEqual({
		headroom: true,
		pendingIdle: true,
		liveReasonEmpty: true,
		abandonedPingRejection: "ping abandoned",
		drainCode: "ConnectionClosed",
		localReasonEmpty: true,
	});
});

test("surfaces the peer's goaway reason in the browser", async ({ page }) => {
	await openApp(page);

	const result: MuxDrainResult = await page.evaluate((options) => window.tb.muxDrainReason(options), {
		url: STACK.muxEndpoint,
		serverCertB64: serverCert,
	});
	expect(result).toEqual({
		slotCode: "Draining",
		reason: "enhance-your-calm",
		emitRejection: "drain observed",
	});
});

test("relays a StreamRefusal code from the page handler to the caller", async ({ page }) => {
	await openApp(page);

	const result: MuxRefusalResult = await page.evaluate((options) => window.tb.muxRefusalRoundTrip(options), {
		url: STACK.muxEndpoint,
		serverCertB64: serverCert,
		payloadHex: PAYLOAD_HEX,
	});
	expect(result).toEqual({
		rejectionName: "TightbeamTransportError",
		rejectionCode: "NotFound",
	});
});

test("parks a server-initiated stream until the page handler registers", async ({ page }) => {
	await openApp(page);

	const result: MuxCallbackResult = await page.evaluate((options) => window.tb.muxParkedCallbackRoundTrip(options), {
		url: STACK.muxEndpoint,
		serverCertB64: serverCert,
		payloadHex: PAYLOAD_HEX,
		replyHex: REPLY_HEX,
	});
	expect(result.servedIds).toEqual(["call-me-parked-browser"]);
	expect(result.relayedIdText).toBe("late-browser-reply");
	expect(result.relayedBodyHex).toBe(REPLY_HEX);
});

test("correlates concurrent cleartext browser emits by stream", async ({ page }) => {
	await openApp(page);

	const result: MuxConcurrentResult = await page.evaluate(
		(options) => window.tb.muxClearConcurrentRoundTrip(options),
		{ url: STACK.muxClearEndpoint, payloadHex: PAYLOAD_HEX },
	);
	expect(result.echoedIds).toEqual(["mux-browser-1", "mux-browser-2", "mux-browser-3"]);
	expect(result.echoedBodiesHex).toEqual([`${PAYLOAD_HEX}00`, `${PAYLOAD_HEX}01`, `${PAYLOAD_HEX}02`]);
});
