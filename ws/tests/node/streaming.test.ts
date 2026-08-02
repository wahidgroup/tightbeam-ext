import { describe, expect, it } from "vitest";

import {
	InternalError,
	Opaque,
	TRANSPORT_ERROR_NAME,
	TightbeamWsClient,
	frame,
} from "@wahidgroup/tightbeam-ws-client";

import {
	certBytes,
	muxClearEndpoint,
	muxDuplexEndpoint,
	muxEndpoint,
} from "../env.js";
import { withClient } from "./harness.js";

const TEXT = new TextDecoder();

/**
 * Origin hop-budget sentinel stamped on every client Open
 * (`tightbeam::constants::DEFAULT_HOP_BUDGET`).
 */
const ORIGIN_HOP_BUDGET = 255;

/**
 * Servlet URN used by the routed openStream / serveStreaming cases.
 */
const SERVLET = "urn:tb:echo";

describe("Node mux body streaming", () => {
	it.each([
		{
			lane: "encrypted",
			connect: () =>
				TightbeamWsClient.connect(
					muxEndpoint,
					certBytes("server.cert.der"),
				),
		},
		{
			lane: "cleartext",
			connect: () => TightbeamWsClient.connectCleartext(muxClearEndpoint),
		},
	] as const)(
		"$lane openStream multi-push echoes a reassembled Frame",
		async ({ connect }) => {
			await withClient(connect, async (client) => {
				const built = await frame(new Uint8Array([0x51, 0x52, 0x53]))
					.withId("stream-open")
					.withOrder(1)
					.build();
				const der = built.toDer();
				const mid = Math.floor(der.length / 2);

				const stream = client.openStream();
				await stream.push(der.subarray(0, mid));
				await stream.push(der.subarray(mid));

				const response = await stream.close();
				expect(response).toBeDefined();
				expect(TEXT.decode(response?.id ?? new Uint8Array())).toBe(
					`routed::${ORIGIN_HOP_BUDGET}`,
				);
				expect(response?.message(Opaque)).toEqual(
					new Uint8Array([0x51, 0x52, 0x53]),
				);
			});
		},
	);

	it.each([
		{
			lane: "encrypted",
			connect: () =>
				TightbeamWsClient.connect(
					muxEndpoint,
					certBytes("server.cert.der"),
				),
		},
		{
			lane: "cleartext",
			connect: () => TightbeamWsClient.connectCleartext(muxClearEndpoint),
		},
	] as const)(
		"$lane openStreamTo stamps the servlet URN on the echoed route",
		async ({ connect }) => {
			await withClient(connect, async (client) => {
				const built = await frame(new Uint8Array([0x61, 0x62]))
					.withId("stream-routed")
					.withOrder(1)
					.build();

				const stream = client.openStreamTo(SERVLET);
				const response = await stream.closeWith(built.toDer());
				expect(response).toBeDefined();
				expect(TEXT.decode(response?.id ?? new Uint8Array())).toBe(
					`routed:${SERVLET}:${ORIGIN_HOP_BUDGET}`,
				);
				expect(response?.message(Opaque)).toEqual(
					new Uint8Array([0x61, 0x62]),
				);
			});
		},
	);

	it("openStreamTo rejects a non-URN target before opening", async () => {
		await withClient(
			() =>
				TightbeamWsClient.connect(
					muxEndpoint,
					certBytes("server.cert.der"),
				),
			async (client) => {
				expect(() => client.openStreamTo("not-a-urn")).toThrow(
					expect.objectContaining({
						name: TRANSPORT_ERROR_NAME,
						code: "InvalidStreamRoute",
					}),
				);
			},
		);
	});

	it("rejects serveStreaming after serve claimed unary mode", async () => {
		await withClient(
			() => TightbeamWsClient.connectCleartext(muxClearEndpoint),
			async (client) => {
				client.serve(() => undefined);

				expect(() =>
					client.serveStreaming(async () => undefined),
				).toThrow(InternalError);
				expect(() =>
					client.serveStreaming(async () => undefined),
				).toThrow(
					expect.objectContaining({
						code: "ServeModeConflict",
						kind: "E_INTERNAL",
					}),
				);
			},
		);
	});

	it("rejects serve after serveStreaming claimed streaming mode", async () => {
		await withClient(
			() => TightbeamWsClient.connectCleartext(muxClearEndpoint),
			async (client) => {
				client.serveStreaming(async () => undefined);

				expect(() => client.serve(() => undefined)).toThrow(
					InternalError,
				);
				expect(() => client.serve(() => undefined)).toThrow(
					expect.objectContaining({
						code: "ServeModeConflict",
						kind: "E_INTERNAL",
					}),
				);
			},
		);
	});

	it("serveStreaming observes the Open route from a routed call-back", async () => {
		await withClient(
			() =>
				TightbeamWsClient.connect(
					muxEndpoint,
					certBytes("server.cert.der"),
				),
			async (client) => {
				const seen: { target?: string; hopsRemaining: number }[] = [];

				client.serveStreaming(async (body, route) => {
					seen.push({
						target: route.target,
						hopsRemaining: route.hopsRemaining,
					});

					for await (const _chunk of body) {
						// Drain the progressive body so the peer's close completes.
					}

					const reply = await frame(new Uint8Array([0xee]))
						.withId("stream-route-reply")
						.withOrder(2)
						.build();
					return reply;
				});

				const built = await frame(new Uint8Array([0xb0, 0x70]))
					.withId(`call-me-stream:${SERVLET}`)
					.withOrder(1)
					.build();

				const response = await client.emit(built);
				expect(seen).toEqual([
					{ target: SERVLET, hopsRemaining: ORIGIN_HOP_BUDGET },
				]);
				expect(TEXT.decode(response?.id ?? new Uint8Array())).toBe(
					"stream-route-reply",
				);
			},
		);
	});

	it("openDuplex echoes chunks on the duplex cleartext server", async () => {
		await withClient(
			() => TightbeamWsClient.connectCleartext(muxDuplexEndpoint),
			async (client) => {
				const duplex = client.openDuplex();
				const first = new Uint8Array([0xd1, 0x01]);
				const second = new Uint8Array([0xd1, 0x02]);

				await duplex.push(first);
				await duplex.push(second);
				await duplex.close();

				const chunks: Uint8Array[] = [];
				for await (const chunk of duplex.body) {
					chunks.push(chunk);
				}

				expect(chunks).toEqual([first, second]);
			},
		);
	});

	it("cancel-on-drop abandons an openStream without close", async () => {
		await withClient(
			() =>
				TightbeamWsClient.connect(
					muxEndpoint,
					certBytes("server.cert.der"),
				),
			async (client) => {
				const built = await frame(new Uint8Array([0xca]))
					.withId("stream-cancel")
					.withOrder(1)
					.build();

				const stream = client.openStream();
				await stream.push(built.toDer());

				// Drop without close: wasm cancel-on-drop. Session stays up.
				void stream;

				const pinged = client.ping();
				await expect(pinged).resolves.toBeUndefined();
			},
		);
	});
});
