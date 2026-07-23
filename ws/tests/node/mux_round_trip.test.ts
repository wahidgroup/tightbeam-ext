import { describe, expect, it } from "vitest";

import type { ConnectOptions } from "@wahidgroup/tightbeam-ws-client";
import {
	Opaque,
	StreamRefusal,
	TRANSPORT_ERROR_NAME,
	TightbeamWsClient,
	frame,
} from "@wahidgroup/tightbeam-ws-client";

import { certBytes, muxClearEndpoint, muxEndpoint } from "../env.js";
import { emitOrFail, withClient } from "./harness.js";

const TEXT = new TextDecoder();
const REPLY_BODY = new Uint8Array([0xca, 0x11, 0xba, 0xc4]);

/**
 * Concurrent streams and the bodies that identify them.
 */
const STREAMS = [
	{ id: "mux-first", body: new Uint8Array([0xb0, 0x01]) },
	{ id: "mux-second", body: new Uint8Array([0xb0, 0x02]) },
	{ id: "mux-third", body: new Uint8Array([0xb0, 0x03]) },
] as const;

/**
 * Both multiplexed lanes: negotiated encrypted sessions and symmetric-cap
 * cleartext sessions behave identically above the transport.
 */
const LANES = [
	{
		lane: "encrypted",
		connect: (options?: ConnectOptions): Promise<TightbeamWsClient> =>
			TightbeamWsClient.connect(
				muxEndpoint,
				certBytes("server.cert.der"),
				8,
				options,
			),
	},
	{
		lane: "cleartext",
		connect: (options?: ConnectOptions): Promise<TightbeamWsClient> =>
			TightbeamWsClient.connectCleartext(muxClearEndpoint, 8, options),
	},
] as const;

describe.each(LANES)(
	"Node multiplexed round-trips against the dockerized $lane mux server",
	({ connect }) => {
		it("correlates each concurrent response to the stream that emitted it", async () => {
			await withClient(connect, async (client) => {
				const emits = STREAMS.map(async (stream, index) => {
					const built = await frame(stream.body)
						.withId(stream.id)
						.withOrder(index + 1)
						.build();

					const response = await emitOrFail(client, built);
					return response;
				});

				const responses = await Promise.all(emits);
				const echoedIds = responses.map((response) =>
					TEXT.decode(response.id),
				);
				const echoedBodies = responses.map((response) =>
					response.message(Opaque),
				);

				expect(echoedIds).toEqual([
					"mux-first",
					"mux-second",
					"mux-third",
				]);
				expect(echoedBodies).toEqual([
					new Uint8Array([0xb0, 0x01]),
					new Uint8Array([0xb0, 0x02]),
					new Uint8Array([0xb0, 0x03]),
				]);
			});
		});

		it("answers a server-initiated stream with the registered handler", async () => {
			await withClient(connect, async (client) => {
				const served: string[] = [];
				client.serve(async (request) => {
					served.push(TEXT.decode(request.id));

					const reply = await frame(REPLY_BODY)
						.withId("client-reply")
						.withOrder(2)
						.build();
					return reply;
				});

				/*
				 * The `call-me` id makes the server call this client back and
				 * relay the handler's reply as the response on this stream.
				 */
				const built = await frame(new Uint8Array([0xb0, 0x09]))
					.withId("call-me-node")
					.withOrder(1)
					.build();
				const response = await emitOrFail(client, built);

				expect(served).toEqual(["call-me-node"]);
				expect(TEXT.decode(response.id)).toBe("client-reply");
				expect(response.message(Opaque)).toEqual(REPLY_BODY);
			});
		});

		it("relays a StreamRefusal code from the handler back to the caller", async () => {
			await withClient(connect, async (client) => {
				/*
				 * The handler refuses the server's call-back stream with a
				 * chosen gRPC status. The echo server relays that failure
				 * as the answer on the original stream, so the code
				 * round-trips: handler throw -> wire status -> caller.
				 */
				client.serve(() => {
					throw new StreamRefusal("NotFound", "nothing here");
				});

				const built = await frame(new Uint8Array([0xb0, 0x23]))
					.withId("call-me-refused")
					.withOrder(1)
					.build();
				await expect(client.emit(built)).rejects.toMatchObject({
					name: TRANSPORT_ERROR_NAME,
					code: "NotFound",
				});
			});
		});

		it("parks server-initiated streams until a handler registers", async () => {
			await withClient(connect, async (client) => {
				/*
				 * Fire the call-back trigger with no handler registered and
				 * give the server's stream time to arrive. No parked-count
				 * surface exists to poll: a sleep too short degrades this
				 * into the ordinary served path, never into a flake.
				 */
				const built = await frame(new Uint8Array([0xb0, 0x0f]))
					.withId("call-me-early")
					.withOrder(1)
					.build();
				const pending = client.emit(built);
				await new Promise((resolve) => setTimeout(resolve, 100));

				const served: string[] = [];
				client.serve(async (request) => {
					served.push(TEXT.decode(request.id));

					const reply = await frame(REPLY_BODY)
						.withId("late-reply")
						.withOrder(2)
						.build();
					return reply;
				});

				const response = await pending;
				expect(served).toEqual(["call-me-early"]);
				expect(TEXT.decode(response?.id ?? new Uint8Array())).toBe(
					"late-reply",
				);
			});
		});

		it("routes new streams to the latest handler after a serve swap", async () => {
			await withClient(connect, async (client) => {
				const makeHandler = (replyId: string) => {
					return async () => {
						const reply = await frame(REPLY_BODY)
							.withId(replyId)
							.withOrder(2)
							.build();
						return reply;
					};
				};
				const callMe = async (idText: string, order: number) => {
					const built = await frame(new Uint8Array([0xb0, 0x12]))
						.withId(idText)
						.withOrder(order)
						.build();
					const response = await emitOrFail(client, built);
					return TEXT.decode(response.id);
				};

				client.serve(makeHandler("first-handler"));
				const beforeSwap = await callMe("call-me-once", 1);

				client.serve(makeHandler("second-handler"));
				const afterSwap = await callMe("call-me-again", 3);

				expect(beforeSwap).toBe("first-handler");
				expect(afterSwap).toBe("second-handler");
			});
		});

		it("reports the negotiated cap on concurrent local streams", async () => {
			await withClient(connect, async (client) => {
				expect(client.maxConcurrentStreams).toBe(8);
			});
		});

		it("drains the session with an application-defined numeric code", async () => {
			await withClient(connect, async (client) => {
				await client.shutdownWith(42);

				const after = await frame(new Uint8Array([0xb0, 0x21]))
					.withId("mux-after-numeric")
					.withOrder(1)
					.build();
				await expect(client.emit(after)).rejects.toMatchObject({
					name: TRANSPORT_ERROR_NAME,
					code: "Draining",
				});
			});
		});

		it("rejects the bare Application label as a GoAway reason", async () => {
			await withClient(connect, async (client) => {
				await expect(
					client.shutdownWith("Application"),
				).rejects.toMatch("a GoAway reason is");
			});
		});

		it("rejects a fresh emit with StreamsExhausted while the cap is full and wakes slot waiters on a free", async () => {
			await withClient(connect, async (client) => {
				/*
				 * The parked handler holds every call-back stream open, so
				 * each call-me emit occupies a local slot until aborted.
				 */
				client.serve(() => new Promise(() => undefined));

				const cap = client.maxConcurrentStreams;
				const controllers: AbortController[] = [];
				const holds: Promise<unknown>[] = [];
				for (let index = 0; index < cap; index += 1) {
					const controller = new AbortController();
					controllers.push(controller);

					const built = await frame(new Uint8Array([0xb0, 0x20]))
						.withId(`call-me-hold-${index}`)
						.withOrder(index + 1)
						.build();
					const hold = client
						.emit(built, { signal: controller.signal })
						.catch((error: unknown) => error);
					holds.push(hold);
				}

				await expect.poll(() => client.hasStreamHeadroom).toBe(false);

				const overflow = await frame(new Uint8Array([0xb0, 0x22]))
					.withId("mux-overflow")
					.withOrder(1)
					.build();
				await expect(client.emit(overflow)).rejects.toMatchObject({
					name: TRANSPORT_ERROR_NAME,
					code: "StreamsExhausted",
				});

				const admitted = client.waitForStreamSlot();
				controllers[0]?.abort(new Error("slot freed"));
				await expect(admitted).resolves.toBeUndefined();

				for (const controller of controllers) {
					controller.abort(new Error("cap release"));
				}
				await Promise.all(holds);
			});
		});

		it("drains the session with an advertised reason on shutdownWith", async () => {
			await withClient(connect, async (client) => {
				await client.shutdownWith("EnhanceYourCalm");

				const after = await frame(new Uint8Array([0xb0, 0x10]))
					.withId("mux-after-calm")
					.withOrder(1)
					.build();
				await expect(client.emit(after)).rejects.toMatchObject({
					name: TRANSPORT_ERROR_NAME,
					code: "Draining",
				});
			});
		});

		it("rejects an abandoned ping with the signal's abort reason", async () => {
			await withClient(connect, async (client) => {
				const controller = new AbortController();
				controller.abort(new Error("ping abandoned"));

				await expect(
					client.ping({ signal: controller.signal }),
				).rejects.toThrow("ping abandoned");
			});
		});

		it("rejects an abandoned stream slot wait with the signal's abort reason", async () => {
			await withClient(connect, async (client) => {
				const controller = new AbortController();
				controller.abort(new Error("wait abandoned"));

				await expect(
					client.waitForStreamSlot({ signal: controller.signal }),
				).rejects.toThrow("wait abandoned");
			});
		});

		it("rejects a stream opened after shutdown with the Draining code", async () => {
			await withClient(connect, async (client) => {
				// Arrange: prove the session is healthy, then drain it.
				const before = await frame(new Uint8Array([0xb0, 0x0a]))
					.withId("mux-before-shutdown")
					.withOrder(1)
					.build();
				await emitOrFail(client, before);
				await client.shutdown();

				const after = await frame(new Uint8Array([0xb0, 0x0b]))
					.withId("mux-after-shutdown")
					.withOrder(2)
					.build();
				await expect(client.emit(after)).rejects.toMatchObject({
					name: TRANSPORT_ERROR_NAME,
					code: "Draining",
				});
			});
		});

		it("rejects an aborted emit with the signal's abort reason", async () => {
			await withClient(connect, async (client) => {
				const built = await frame(new Uint8Array([0xb0, 0x0c]))
					.withId("mux-aborted")
					.withOrder(1)
					.build();

				const controller = new AbortController();
				const pending = client.emit(built, {
					signal: controller.signal,
				});
				controller.abort(new Error("cancelled by test"));

				await expect(pending).rejects.toThrow("cancelled by test");
			});
		});

		it("acknowledges a connection-level liveness ping", async () => {
			await withClient(connect, async (client) => {
				await expect(client.ping()).resolves.toBeUndefined();
			});
		});

		it("reports stream headroom until the session drains", async () => {
			await withClient(connect, async (client) => {
				const healthy = client.hasStreamHeadroom;
				await client.shutdown();
				const draining = client.hasStreamHeadroom;

				expect(healthy).toBe(true);
				expect(draining).toBe(false);
			});
		});

		it("reports pending streams while an emit awaits its response", async () => {
			await withClient(connect, async (client) => {
				/*
				 * The parked handler keeps the server's call-back stream,
				 * and with it this emit, pending until the abort below.
				 */
				client.serve(() => new Promise(() => undefined));
				const idle = client.hasPendingStreams;

				const built = await frame(new Uint8Array([0xb0, 0x11]))
					.withId("call-me-pending")
					.withOrder(1)
					.build();
				const controller = new AbortController();
				const pending = client.emit(built, {
					signal: controller.signal,
				});

				await expect.poll(() => client.hasPendingStreams).toBe(true);
				expect(idle).toBe(false);

				controller.abort(new Error("pending observed"));
				await expect(pending).rejects.toThrow("pending observed");
				expect(client.hasPendingStreams).toBe(false);
			});
		});

		it("reports no goaway reason while the connection is live", async () => {
			await withClient(connect, async (client) => {
				expect(client.goawayReason).toBeUndefined();
				expect(client.goawayCode).toBeUndefined();
			});
		});

		it("leaves the goaway reason empty after a local shutdown", async () => {
			await withClient(connect, async (client) => {
				/*
				 * A local drain carries no peer reason: the caller already
				 * knows why the session ended.
				 */
				await client.shutdown();

				expect(client.goawayReason).toBeUndefined();
			});
		});

		it("surfaces the peer's goaway reason for reconnect policy", async () => {
			await withClient(connect, async (client) => {
				/*
				 * The `drain-calm` id makes the server drain the session
				 * with an EnhanceYourCalm GoAway instead of echoing. The
				 * drain stops the server's writer before the response, so
				 * the emit never settles on its own and is aborted once
				 * the reason surfaces.
				 */
				const drain = await frame(new Uint8Array([0xb0, 0x0d]))
					.withId("drain-calm")
					.withOrder(1)
					.build();
				const controller = new AbortController();
				const pending = client.emit(drain, {
					signal: controller.signal,
				});

				await expect
					.poll(() => client.goawayReason)
					.toBe("EnhanceYourCalm");
				expect(client.goawayCode).toBe(2);

				controller.abort(new Error("drain observed"));
				await expect(pending).rejects.toThrow("drain observed");
			});
		});

		it("admits a stream slot immediately when headroom exists", async () => {
			await withClient(connect, async (client) => {
				await expect(
					client.waitForStreamSlot(),
				).resolves.toBeUndefined();
			});
		});

		it("rejects a stream slot wait with Draining once the session drains", async () => {
			await withClient(connect, async (client) => {
				await client.shutdown();

				await expect(client.waitForStreamSlot()).rejects.toMatchObject({
					name: TRANSPORT_ERROR_NAME,
					code: "Draining",
				});
			});
		});

		it("settles an in-flight emit when the client closes", async () => {
			await withClient(connect, async (client) => {
				client.serve(() => new Promise(() => undefined));

				const built = await frame(new Uint8Array([0xb0, 0x0e]))
					.withId("call-me-parked")
					.withOrder(1)
					.build();
				const pending = client.emit(built);

				client.close();

				await expect(pending).rejects.toMatchObject({
					name: TRANSPORT_ERROR_NAME,
					code: "ConnectionClosed",
				});
			});
		});

		it("rejects a connect aborted by its signal", async () => {
			const controller = new AbortController();
			controller.abort(new Error("connect cancelled"));

			await expect(
				connect({ signal: controller.signal }),
			).rejects.toThrow("connect cancelled");
		});

		it("resolves the closed promise once the socket closes", async () => {
			await withClient(connect, async (client) => {
				const observed = client.closed;

				await client.shutdown();
				client.close();

				/*
				 * The close code and cleanliness vary by runtime and by who
				 * wins the closing race. The behavior under test is that
				 * closure is observable at all, carrying the close info.
				 */
				await expect(observed).resolves.toMatchObject({
					code: expect.any(Number),
					reason: expect.any(String),
					wasClean: expect.any(Boolean),
				});
			});
		});
	},
);

describe("released client behavior", () => {
	/**
	 * Every operation that calls into the wasm socket, expected to reject
	 * in a defined way once the client has released it.
	 */
	const OPERATIONS = [
		{
			name: "emit",
			run: async (client: TightbeamWsClient): Promise<void> => {
				const built = await frame(new Uint8Array([0xb0, 0x0f]))
					.withId("post-close")
					.withOrder(1)
					.build();
				await client.emit(built);
			},
		},
		{
			name: "serve",
			run: async (client: TightbeamWsClient): Promise<void> => {
				client.serve(() => undefined);
			},
		},
		{
			name: "ping",
			run: async (client: TightbeamWsClient): Promise<void> => {
				await client.ping();
			},
		},
		{
			name: "waitForStreamSlot",
			run: async (client: TightbeamWsClient): Promise<void> => {
				await client.waitForStreamSlot();
			},
		},
		{
			name: "shutdown",
			run: async (client: TightbeamWsClient): Promise<void> => {
				await client.shutdown();
			},
		},
		{
			name: "shutdownWith",
			run: async (client: TightbeamWsClient): Promise<void> => {
				await client.shutdownWith("Shutdown");
			},
		},
	] as const;

	it.each(OPERATIONS)(
		"rejects $name on a released client with ConnectionClosed",
		async ({ run }) => {
			const client = await TightbeamWsClient.connectCleartext(
				muxClearEndpoint,
				8,
			);
			client.close();

			await expect(run(client)).rejects.toMatchObject({
				name: TRANSPORT_ERROR_NAME,
				code: "ConnectionClosed",
			});
		},
	);

	it("keeps the lifecycle surfaces readable after close", async () => {
		const client = await TightbeamWsClient.connectCleartext(
			muxClearEndpoint,
			8,
		);
		const capBeforeClose = client.maxConcurrentStreams;

		client.close();

		expect(client.readyState).toBe(WebSocket.CLOSED);
		expect(client.maxConcurrentStreams).toBe(capBeforeClose);
		expect(client.hasStreamHeadroom).toBe(false);
		expect(client.hasPendingStreams).toBe(false);
		expect(client.goawayReason).toBeUndefined();
		expect(client.goawayCode).toBeUndefined();

		await expect(client.closed).resolves.toMatchObject({
			code: expect.any(Number),
			reason: expect.any(String),
			wasClean: expect.any(Boolean),
		});
	});
});

describe("cleartext dial readiness", () => {
	it("rejects a dial to a dead endpoint with ConnectionClosed", async () => {
		/*
		 * The discard port: nothing listens there, so the dial closes
		 * before it opens.
		 */
		const deadEndpoint = "ws://127.0.0.1:9";

		await expect(
			TightbeamWsClient.connectCleartext(deadEndpoint, 8),
		).rejects.toMatchObject({
			name: TRANSPORT_ERROR_NAME,
			code: "ConnectionClosed",
		});
	});
});
