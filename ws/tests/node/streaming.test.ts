import { describe, expect, it } from "vitest";

import type { DuplexStream } from "@wahidgroup/tightbeam-ws-client";
import {
	ClientTransportError,
	TightbeamWsClient,
} from "@wahidgroup/tightbeam-ws-client";

import { certBytes } from "../env.js";
import { withClient } from "../fixtures.js";
import { STACK } from "../stack.js";

/**
 * The options of every cleartext dial: the stream cap of the stack, which no
 * handshake negotiates.
 */
const CLEARTEXT = { streams: STACK.streams };

const ENGINE = await TightbeamWsClient.init();

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

/**
 * The refusal of a call on a stream that a close or a disposal released.
 */
const STREAM_CLOSED = { name: ClientTransportError.NAME, code: "StreamClosed" };

/**
 * A body larger than the initial stream credit of a peer (64 chunks of
 * 16 KiB), so a push of it waits for the peer's grants.
 */
const PAST_INITIAL_CREDIT = new Uint8Array(2 * 1024 * 1024).fill(0x5a);

/**
 * The chunks every duplex body case pushes to the duplex echo server.
 */
const DUPLEX_CHUNKS = [
	new Uint8Array([0xe1, 0x01]),
	new Uint8Array([0xe1, 0x02]),
	new Uint8Array([0xe1, 0x03]),
] as const;

/**
 * Dial the duplex echo server, which answers each chunk with the same octets.
 */
function connectDuplex(): Promise<TightbeamWsClient> {
	const dialing = ENGINE.connectCleartext(STACK.muxDuplexEndpoint, CLEARTEXT);
	return dialing;
}

/**
 * Push {@link DUPLEX_CHUNKS} on `duplex`, then close its request half, so the
 * reply body holds each chunk in turn.
 */
async function pushEvery(duplex: DuplexStream): Promise<void> {
	for (const chunk of DUPLEX_CHUNKS) {
		await duplex.push(chunk);
	}

	await duplex.close();
}

/**
 * Every chunk that `body` yields until it ends.
 */
async function collected(
	body: AsyncIterable<Uint8Array>,
): Promise<Uint8Array[]> {
	const chunks: Uint8Array[] = [];
	for await (const chunk of body) {
		chunks.push(chunk);
	}

	return chunks;
}

/**
 * A weak reference to the next chunk of `reads`, made in a frame of its own,
 * so the caller holds no strong reference to the chunk.
 */
async function nextChunkRef(
	reads: AsyncIterator<Uint8Array>,
): Promise<WeakRef<Uint8Array>> {
	const read = await reads.next();
	if (read.done === true) {
		throw new Error("the body ended before its first chunk");
	}

	const ref = new WeakRef(read.value);
	return ref;
}

/**
 * Collect garbage once the current job ends, so a weak reference made in it
 * can clear. The lane runs with `--expose-gc`.
 */
async function collectGarbage(): Promise<void> {
	await new Promise((resolve) => {
		setTimeout(resolve, 0);
	});

	const gc = globalThis.gc;
	if (gc === undefined) {
		throw new Error("the node lane runs with --expose-gc");
	}

	gc();
}

/**
 * The first chunk of `body`, read by a loop that leaves with a `break`.
 */
async function firstChunk(
	body: AsyncIterable<Uint8Array>,
): Promise<Uint8Array | undefined> {
	let first: Uint8Array | undefined;
	for await (const chunk of body) {
		first = chunk;
		break;
	}

	return first;
}

describe("Node mux body streaming", () => {
	it.each([
		{
			lane: "encrypted",
			connect: () =>
				ENGINE.connect(STACK.muxEndpoint, certBytes("server.cert.der")),
		},
		{
			lane: "cleartext",
			connect: () =>
				ENGINE.connectCleartext(STACK.muxClearEndpoint, CLEARTEXT),
		},
	] as const)(
		"$lane openStream multi-push echoes a reassembled Frame",
		async ({ connect }) => {
			await withClient(connect, async (client) => {
				const built = await ENGINE.frameBuilder(
					new Uint8Array([0x51, 0x52, 0x53]),
				)
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
				expect(response?.message(ENGINE.opaque)).toEqual(
					new Uint8Array([0x51, 0x52, 0x53]),
				);
			});
		},
	);

	it.each([
		{
			lane: "encrypted",
			connect: () =>
				ENGINE.connect(STACK.muxEndpoint, certBytes("server.cert.der")),
		},
		{
			lane: "cleartext",
			connect: () =>
				ENGINE.connectCleartext(STACK.muxClearEndpoint, CLEARTEXT),
		},
	] as const)(
		"$lane openStreamTo stamps the servlet URN on the echoed route",
		async ({ connect }) => {
			await withClient(connect, async (client) => {
				const built = await ENGINE.frameBuilder(
					new Uint8Array([0x61, 0x62]),
				)
					.withId("stream-routed")
					.withOrder(1)
					.build();

				const stream = client.openStreamTo(SERVLET);
				const response = await stream.closeWith(built.toDer());
				expect(response).toBeDefined();
				expect(TEXT.decode(response?.id ?? new Uint8Array())).toBe(
					`routed:${SERVLET}:${ORIGIN_HOP_BUDGET}`,
				);
				expect(response?.message(ENGINE.opaque)).toEqual(
					new Uint8Array([0x61, 0x62]),
				);
			});
		},
	);

	it("openStreamTo rejects a non-URN target before opening", async () => {
		await withClient(
			() =>
				ENGINE.connect(STACK.muxEndpoint, certBytes("server.cert.der")),
			async (client) => {
				expect(() => client.openStreamTo("not-a-urn")).toThrow(
					expect.objectContaining({
						name: ClientTransportError.NAME,
						code: "InvalidStreamRoute",
					}),
				);
			},
		);
	});

	it("rejects serveStreaming after serve claimed unary mode", async () => {
		await withClient(
			() => ENGINE.connectCleartext(STACK.muxClearEndpoint, CLEARTEXT),
			async (client) => {
				client.serve(() => undefined);

				const claimStreaming = (): void => {
					client.serveStreaming(async () => undefined);
				};
				expect(claimStreaming).toThrow(
					expect.objectContaining({
						name: ClientTransportError.NAME,
						code: "ServeModeConflict",
					}),
				);
			},
		);
	});

	it("rejects serve after serveStreaming claimed streaming mode", async () => {
		await withClient(
			() => ENGINE.connectCleartext(STACK.muxClearEndpoint, CLEARTEXT),
			async (client) => {
				client.serveStreaming(async () => undefined);

				const claimUnary = (): void => {
					client.serve(() => undefined);
				};
				expect(claimUnary).toThrow(
					expect.objectContaining({
						name: ClientTransportError.NAME,
						code: "ServeModeConflict",
					}),
				);
			},
		);
	});

	it("serveStreaming observes the Open route from a routed call-back", async () => {
		await withClient(
			() =>
				ENGINE.connect(STACK.muxEndpoint, certBytes("server.cert.der")),
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

					const reply = await ENGINE.frameBuilder(
						new Uint8Array([0xee]),
					)
						.withId("stream-route-reply")
						.withOrder(2)
						.build();
					return reply;
				});

				const built = await ENGINE.frameBuilder(
					new Uint8Array([0xb0, 0x70]),
				)
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
			() => ENGINE.connectCleartext(STACK.muxDuplexEndpoint, CLEARTEXT),
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

	it("a disposed request stream cancels and frees", async () => {
		await withClient(
			() =>
				ENGINE.connect(STACK.muxEndpoint, certBytes("server.cert.der")),
			async (client) => {
				const built = await ENGINE.frameBuilder(new Uint8Array([0xca]))
					.withId("stream-cancel")
					.withOrder(1)
					.build();

				const stream = client.openStream();
				await stream.push(built.toDer());
				await stream[Symbol.asyncDispose]();

				expect(client.hasPendingStreams).toBe(false);
				await expect(stream.push(built.toDer())).rejects.toMatchObject(
					STREAM_CLOSED,
				);
			},
		);
	});

	it("a disposed duplex stream cancels and releases", async () => {
		await withClient(
			() => ENGINE.connectCleartext(STACK.muxDuplexEndpoint, CLEARTEXT),
			async (client) => {
				const chunk = new Uint8Array([0xd2, 0x01]);

				const duplex = client.openDuplex();
				await duplex.push(chunk);
				await duplex[Symbol.asyncDispose]();

				expect(client.hasPendingStreams).toBe(false);
				await expect(duplex.push(chunk)).rejects.toMatchObject(
					STREAM_CLOSED,
				);
			},
		);
	});

	it("a close during a push completes after the push, with no cancel", async () => {
		await withClient(
			() => ENGINE.connectCleartext(STACK.muxClearEndpoint, CLEARTEXT),
			async (client) => {
				const built = await ENGINE.frameBuilder(PAST_INITIAL_CREDIT)
					.withId("stream-ordered")
					.withOrder(1)
					.build();

				const stream = client.openStream();
				const pushed = stream.push(built.toDer());
				const response = await stream.close();

				await expect(pushed).resolves.toBeUndefined();
				expect(response?.message(ENGINE.opaque)).toEqual(
					PAST_INITIAL_CREDIT,
				);
			},
		);
	});

	it("a second close refuses with StreamClosed", async () => {
		await withClient(
			() => ENGINE.connectCleartext(STACK.muxClearEndpoint, CLEARTEXT),
			async (client) => {
				const built = await ENGINE.frameBuilder(new Uint8Array([0xc1]))
					.withId("stream-closed")
					.withOrder(1)
					.build();

				const stream = client.openStream();
				await stream.closeWith(built.toDer());

				const second = stream.close();
				await expect(second).rejects.toMatchObject(STREAM_CLOSED);
			},
		);
	});

	it("overlapping loops over a duplex body both finish without StreamBusy", async () => {
		await withClient(connectDuplex, async (client) => {
			const duplex = client.openDuplex();
			const first = collected(duplex.body);
			const second = collected(duplex.body);
			await pushEvery(duplex);
			const loops = await Promise.all([first, second]);

			const read = loops.flat();
			const everyChunk = expect.arrayContaining([...DUPLEX_CHUNKS]);
			expect(read).toHaveLength(DUPLEX_CHUNKS.length);
			expect(read).toEqual(everyChunk);
		});
	});

	it("a break out of a duplex body before its close cancels the stream", async () => {
		await withClient(connectDuplex, async (client) => {
			const duplex = client.openDuplex();
			await duplex.push(DUPLEX_CHUNKS[0]);

			const first = await firstChunk(duplex.body);
			const rest = await collected(duplex.body);
			expect(first).toEqual(DUPLEX_CHUNKS[0]);
			expect(rest).toEqual([]);
			expect(client.hasPendingStreams).toBe(false);
		});
	});

	it("a duplex body read to its end keeps no chunk it yielded", async () => {
		await withClient(connectDuplex, async (client) => {
			const duplex = client.openDuplex();
			const reads = duplex.body[Symbol.asyncIterator]();
			await pushEvery(duplex);

			const first = await nextChunkRef(reads);
			const rest = await collected(duplex.body);
			await collectGarbage();
			expect(rest).toHaveLength(DUPLEX_CHUNKS.length - 1);
			expect(first.deref()).toBeUndefined();
		});
	});

	it("a return while a read of an opened duplex body waits ends the read quietly and cancels the stream", async () => {
		await withClient(connectDuplex, async (client) => {
			const duplex = client.openDuplex();
			const reads = duplex.body[Symbol.asyncIterator]();
			await duplex.push(DUPLEX_CHUNKS[0]);
			const first = await reads.next();
			const waiting = reads.next();

			await duplex.body[Symbol.asyncDispose]();
			const ended = await waiting;
			const pending = client.hasPendingStreams;
			await duplex[Symbol.asyncDispose]();
			expect(first).toEqual({ value: DUPLEX_CHUNKS[0], done: false });
			expect(ended).toEqual({ value: undefined, done: true });
			expect(pending).toBe(false);
		});
	});

	it("a served duplex handler that settles before it drains its body still answers its status", async () => {
		await withClient(
			() => ENGINE.connectCleartext(STACK.muxClearEndpoint, CLEARTEXT),
			async (client) => {
				client.serveDuplex(() => "PermissionDenied");
				const callMe = await ENGINE.frameBuilder(new Uint8Array([0xd5]))
					.withId("call-me-duplex")
					.withOrder(1)
					.build();

				const answered = client.emit(callMe);
				await expect(answered).rejects.toMatchObject({
					code: "PermissionDenied",
				});
			},
		);
	});
});
