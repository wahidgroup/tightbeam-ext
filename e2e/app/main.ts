/**
 * Minimal, headless example app for the generic tightbeam-ws client.
 *
 * Builds frames with the fluent {@link frame} builder, ships them over the
 * socket, and surfaces the decoded response so the Playwright spec can assert
 * the body and metadata survived the round-trip.
 */

import { TightbeamWsClient, frame } from "@wahidgroup/tightbeam-ws-client";

const TEXT = new TextDecoder();

/**
 * The decoded outcome of a single round-trip, in a structured-clone-safe shape
 * (no `bigint`) so it crosses the Playwright `page.evaluate` boundary.
 */
export interface RoundTripResult {
	readonly bodyHex: string;
	readonly version: number;
	readonly idText: string;
	readonly order: string;
	readonly signed: boolean;
	readonly messageIntegrity: boolean;
	readonly frameIntegrity: boolean;
}

function hexToBytes(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i += 1) {
		bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}

	return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
	let hex = "";
	for (const byte of bytes) {
		hex += byte.toString(16).padStart(2, "0");
	}

	return hex;
}

async function roundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<RoundTripResult> {
	const client = await TightbeamWsClient.connect(url);
	try {
		const built = frame(hexToBytes(payloadHex))
			.withId(idText)
			.withOrder(order)
			.build();
		const opened = await client.exchange(built);

		return {
			bodyHex: bytesToHex(opened.body),
			version: opened.version,
			idText: TEXT.decode(opened.id),
			order: opened.order.toString(),
			signed: opened.signed,
			messageIntegrity: opened.messageIntegrity,
			frameIntegrity: opened.frameIntegrity,
		};
	} finally {
		client.close();
	}
}

window.tbRoundTrip = roundTrip;

const status = document.querySelector("#status");
if (status) {
	status.textContent = "client ready";
}
