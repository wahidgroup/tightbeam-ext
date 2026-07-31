import { describe, expect, it } from "vitest";

import {
	Opaque,
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
				if (response === undefined) {
					return;
				}

				expect(TEXT.decode(response.id)).toBe("stream-open");
				expect(response.message(Opaque)).toEqual(
					new Uint8Array([0x51, 0x52, 0x53]),
				);
			});
		},
	);

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
				// Drop without close: wasm cancel-on-drop; session stays up.
				void stream;
				const pinged = client.ping();
				await expect(pinged).resolves.toBeUndefined();
			},
		);
	});
});
