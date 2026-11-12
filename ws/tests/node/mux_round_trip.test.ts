import { describe, expect, it } from "vitest";

import type { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";
import { Engine, StreamRefusal } from "@wahidgroup/tightbeam-ws-client";

import { EchoDials } from "../fixtures.js";
import { STACK } from "../stack.js";

const ENGINE = await Engine.load();

/**
 * The dials of this lane against the echo servers of the stack.
 */
const DIALS = EchoDials.of(ENGINE, STACK);

const TEXT = new TextDecoder();
const REPLY_BODY = new Uint8Array([0xca, 0x11, 0xba, 0xc4]);

/**
 * The servlet a routed call-back names.
 */
const SERVLET = "urn:tb:echo";

/**
 * Concurrent streams and the bodies that identify them.
 */
const STREAMS = [
	{ id: "mux-first", body: new Uint8Array([0xb0, 0x01]) },
	{ id: "mux-second", body: new Uint8Array([0xb0, 0x02]) },
	{ id: "mux-third", body: new Uint8Array([0xb0, 0x03]) },
] as const;

describe.each(DIALS.lanes)("Node multiplexed round-trips against the dockerized $lane mux server", ({ connect }) => {
	it("correlates each concurrent response to the stream that emitted it", async () => {
		await using client = await connect();
		const emits = STREAMS.map(async (stream, index) => {
			const built = await ENGINE.frameBuilder(stream.body)
				.withId(stream.id)
				.withOrder(index + 1)
				.build();

			const response = await EchoDials.emitOrFail(client, built);
			return response;
		});

		const responses = await Promise.all(emits);
		const echoedIds = responses.map((response) => TEXT.decode(response.id));
		const echoedBodies = await Promise.all(responses.map((response) => response.open(ENGINE.opaque)));

		expect(echoedIds).toEqual(["mux-first", "mux-second", "mux-third"]);
		expect(echoedBodies).toEqual([
			new Uint8Array([0xb0, 0x01]),
			new Uint8Array([0xb0, 0x02]),
			new Uint8Array([0xb0, 0x03]),
		]);
	});

	it("answers a server-initiated stream with the registered handler", async () => {
		await using client = await connect();
		const served: string[] = [];
		client.serve(async (request) => {
			served.push(TEXT.decode(request.id));

			const reply = await ENGINE.frameBuilder(REPLY_BODY).withId("client-reply").withOrder(2).build();
			return reply;
		});

		/*
		 * The `call-me` id makes the server call this client back and
		 * relay the handler's reply as the response on this stream.
		 */
		const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x09]))
			.withId("call-me-node")
			.withOrder(1)
			.build();

		const response = await EchoDials.emitOrFail(client, built);
		expect(served).toEqual(["call-me-node"]);
		expect(TEXT.decode(response.id)).toBe("client-reply");
		expect(await response.open(ENGINE.opaque)).toEqual(REPLY_BODY);
	});

	it("accepts a bodiless null answer from the handler", async () => {
		await using client = await connect();
		/*
		 * `null` and `undefined` both mean a bodiless acceptance.
		 * The server relays it as a response without a frame, so
		 * the original emit resolves with undefined.
		 */
		client.serve(() => null);

		const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x24]))
			.withId("call-me-bodiless")
			.withOrder(1)
			.build();
		await expect(client.emit(built)).resolves.toBeUndefined();
	});

	it("relays a StreamRefusal code from the handler back to the caller", async () => {
		await using client = await connect();
		/*
		 * The handler refuses the call-back stream of the server, and
		 * the echo server relays that status as the answer of the
		 * original stream.
		 */
		client.serve(() => {
			throw new StreamRefusal("NotFound", "nothing here");
		});

		const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x23]))
			.withId("call-me-refused")
			.withOrder(1)
			.build();
		await expect(client.emit(built)).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "NotFound",
		});
	});

	it("relays a StreamRefusal code from a streaming handler back to the caller", async () => {
		await using client = await connect();
		/*
		 * The twin of the unary relay: the echo server opens a
		 * routed progressive call-back, the streaming handler
		 * refuses it, and the code round-trips to the caller.
		 */
		client.serveStreaming(() => {
			throw new StreamRefusal("NotFound", "nothing here");
		});

		const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x25]))
			.withId(`call-me-stream:${SERVLET}`)
			.withOrder(1)
			.build();
		await expect(client.emit(built)).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "NotFound",
		});
	});

	it("answers Unknown for a handler that rethrows a peer refusal", async () => {
		await using client = await connect();
		/*
		 * The echo server refuses the inner emit with
		 * InvalidArgument, and the handler rethrows that refusal.
		 * Only a StreamRefusal names the status of a stream.
		 */
		client.serve(async () => {
			const inner = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x26]))
				.withId("call-me-stream:")
				.withOrder(1)
				.build();
			await client.emit(inner);
			return undefined;
		});

		const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x27]))
			.withId("call-me-rethrown")
			.withOrder(1)
			.build();
		await expect(client.emit(built)).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "Unknown",
		});
	});

	it("answers Unknown for a handler that throws a bare status name", async () => {
		await using client = await connect();
		client.serve(() => {
			throw "NotFound";
		});

		const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x28]))
			.withId("call-me-named")
			.withOrder(1)
			.build();
		await expect(client.emit(built)).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "Unknown",
		});
	});

	it("parks server-initiated streams until a handler registers", async () => {
		await using client = await connect();
		/*
		 * The emit takes its stream slot before it returns, so the
		 * Open of the peer parks until the handler registers.
		 */
		const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x0f]))
			.withId("call-me-early")
			.withOrder(1)
			.build();
		const pending = client.emit(built);
		expect(client.hasPendingStreams).toBe(true);

		const served: string[] = [];
		client.serve(async (request) => {
			served.push(TEXT.decode(request.id));

			const reply = await ENGINE.frameBuilder(REPLY_BODY).withId("late-reply").withOrder(2).build();
			return reply;
		});

		const response = await pending;
		expect(served).toEqual(["call-me-early"]);
		expect(TEXT.decode(response?.id ?? new Uint8Array())).toBe("late-reply");
	});

	it("routes new streams to the latest handler after a serve swap", async () => {
		await using client = await connect();
		const makeHandler = (replyId: string) => {
			return async () => {
				const reply = await ENGINE.frameBuilder(REPLY_BODY).withId(replyId).withOrder(2).build();
				return reply;
			};
		};
		const callMe = async (idText: string, order: number) => {
			const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x12]))
				.withId(idText)
				.withOrder(order)
				.build();
			const response = await EchoDials.emitOrFail(client, built);
			return TEXT.decode(response.id);
		};

		client.serve(makeHandler("first-handler"));
		const beforeSwap = await callMe("call-me-once", 1);
		client.serve(makeHandler("second-handler"));

		const afterSwap = await callMe("call-me-again", 3);
		expect(beforeSwap).toBe("first-handler");
		expect(afterSwap).toBe("second-handler");
	});

	it("reports the negotiated cap on concurrent local streams", async () => {
		await using client = await connect();
		expect(client.maxConcurrentStreams).toBe(STACK.dial.streams);
	});

	it("drains the session with an application-defined numeric code", async () => {
		await using client = await connect();
		await client.shutdownWith(42);

		const after = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x21]))
			.withId("mux-after-numeric")
			.withOrder(1)
			.build();
		await expect(client.emit(after)).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "ConnectionClosed",
		});
	});

	it("rejects the bare application label as a GoAway reason", async () => {
		await using client = await connect();
		await expect(
			// @ts-expect-error A bare label fails at runtime.
			client.shutdownWith("application"),
		).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "InvalidGoAwayReason",
		});
	});

	it("rejects a fresh emit with StreamsExhausted while the cap is full and wakes slot waiters on a free", async () => {
		await using client = await connect();
		/*
		 * The parked handler holds every call-back stream open, so
		 * each call-me emit takes a local slot as it is called and
		 * holds it until aborted.
		 */
		client.serve(() => new Promise(() => undefined));

		const cap = client.maxConcurrentStreams;
		const controllers: AbortController[] = [];
		const holds: Promise<unknown>[] = [];
		for (let index = 0; index < cap; index += 1) {
			const controller = new AbortController();
			controllers.push(controller);

			const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x20]))
				.withId(`call-me-hold-${index}`)
				.withOrder(index + 1)
				.build();

			const hold = client.emit(built, { signal: controller.signal }).catch((error: unknown) => error);
			holds.push(hold);
		}

		expect(client.hasStreamHeadroom).toBe(false);

		const overflow = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x22]))
			.withId("mux-overflow")
			.withOrder(1)
			.build();
		await expect(client.emit(overflow)).rejects.toMatchObject({
			name: "TightbeamTransportError",
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

	it("drains the session with an advertised reason on shutdownWith", async () => {
		await using client = await connect();
		await client.shutdownWith("enhance-your-calm");

		const after = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x10]))
			.withId("mux-after-calm")
			.withOrder(1)
			.build();
		await expect(client.emit(after)).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "ConnectionClosed",
		});
	});

	it("rejects an abandoned ping with the signal's abort reason", async () => {
		await using client = await connect();
		const controller = new AbortController();
		controller.abort(new Error("ping abandoned"));

		await expect(client.ping({ signal: controller.signal })).rejects.toThrow("ping abandoned");
	});

	it("rejects an abandoned stream slot wait with the signal's abort reason", async () => {
		await using client = await connect();
		const controller = new AbortController();
		controller.abort(new Error("wait abandoned"));

		await expect(client.waitForStreamSlot({ signal: controller.signal })).rejects.toThrow("wait abandoned");
	});

	it("rejects a stream opened after a finished shutdown as closed", async () => {
		await using client = await connect();
		const before = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x0a]))
			.withId("mux-before-shutdown")
			.withOrder(1)
			.build();

		await EchoDials.emitOrFail(client, before);
		await client.shutdown();

		const after = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x0b]))
			.withId("mux-after-shutdown")
			.withOrder(2)
			.build();

		await expect(client.emit(after)).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "ConnectionClosed",
		});
	});

	it("rejects an aborted emit with the signal's abort reason", async () => {
		await using client = await connect();
		const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x0c]))
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

	it("acknowledges a connection-level liveness ping", async () => {
		await using client = await connect();
		await expect(client.ping()).resolves.toBeUndefined();
	});

	it("reports stream headroom until the session drains", async () => {
		await using client = await connect();
		const healthy = client.hasStreamHeadroom;

		await client.shutdown();

		const draining = client.hasStreamHeadroom;
		expect(healthy).toBe(true);
		expect(draining).toBe(false);
	});

	it("reports pending streams while an emit awaits its response", async () => {
		await using client = await connect();
		/*
		 * The parked handler keeps the server's call-back stream,
		 * and with it this emit, pending until the abort below.
		 */
		client.serve(() => new Promise(() => undefined));

		const idle = client.hasPendingStreams;
		const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x11]))
			.withId("call-me-pending")
			.withOrder(1)
			.build();

		const controller = new AbortController();
		const pending = client.emit(built, {
			signal: controller.signal,
		});

		expect(client.hasPendingStreams).toBe(true);
		expect(idle).toBe(false);

		controller.abort(new Error("pending observed"));
		await expect(pending).rejects.toThrow("pending observed");
		expect(client.hasPendingStreams).toBe(false);
	});

	it("reports no goaway reason while the connection is live", async () => {
		await using client = await connect();
		expect(client.goawayReason).toBeUndefined();
		expect(client.goawayCode).toBeUndefined();
	});

	it("leaves the goaway reason empty after a local shutdown", async () => {
		await using client = await connect();
		/*
		 * A local drain carries no peer reason: the caller already
		 * knows why the session ended.
		 */
		await client.shutdown();

		expect(client.goawayReason).toBeUndefined();
	});

	it("surfaces the peer's goaway reason for reconnect policy", async () => {
		await using client = await connect();
		/*
		 * Parked call-backs hold every slot but the one that the
		 * `drain-calm` id takes, and its EnhanceYourCalm GoAway wakes
		 * the parked slot wait with `Draining`.
		 */
		client.serve(() => new Promise(() => undefined));

		const holds = await Promise.all(
			Array.from({ length: client.maxConcurrentStreams - 1 }, (_, index) =>
				ENGINE.frameBuilder(new Uint8Array([0xb0, 0x0c]))
					.withId(`call-me-drain-${index}`)
					.withOrder(index + 1)
					.build(),
			),
		);
		const drain = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x0d]))
			.withId("drain-calm")
			.withOrder(1)
			.build();

		const controller = new AbortController();
		const signal = controller.signal;
		const held = holds.map((frame) => client.emit(frame, { signal }).catch((error: unknown) => error));

		const pending = client.emit(drain, { signal });

		await expect(client.waitForStreamSlot()).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "Draining",
		});
		expect(client.goawayReason).toBe("enhance-your-calm");

		controller.abort(new Error("drain observed"));
		await expect(pending).rejects.toThrow("drain observed");
		await Promise.all(held);
	});

	it("admits a stream slot immediately when headroom exists", async () => {
		await using client = await connect();
		await expect(client.waitForStreamSlot()).resolves.toBeUndefined();
	});

	it("rejects a stream slot wait as closed once a shutdown finishes", async () => {
		await using client = await connect();
		await client.shutdown();

		await expect(client.waitForStreamSlot()).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "ConnectionClosed",
		});
	});

	it("settles an in-flight emit when the client closes", async () => {
		await using client = await connect();
		client.serve(() => new Promise(() => undefined));

		const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x0e]))
			.withId("call-me-parked")
			.withOrder(1)
			.build();

		const pending = client.emit(built);
		const closing = client.close();
		await expect(pending).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "ConnectionClosed",
		});
		await closing;
	});

	it("rejects a connect aborted by its signal", async () => {
		const controller = new AbortController();
		controller.abort(new Error("connect cancelled"));

		await expect(connect({ signal: controller.signal })).rejects.toThrow("connect cancelled");
	});

	it("resolves the closed promise once the socket closes", async () => {
		await using client = await connect();
		const observed = client.closed;

		await client.shutdown();
		await client.close();

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

describe("released client behavior", () => {
	/**
	 * Every operation that calls into the wasm socket, expected to reject
	 * in a defined way once the client has released it.
	 */
	const OPERATIONS = [
		{
			name: "emit",
			run: async (client: TightbeamWsClient): Promise<void> => {
				const built = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x0f]))
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
				await client.shutdownWith("shutdown");
			},
		},
	] as const;

	it.each(OPERATIONS)("rejects $name on a released client with ConnectionClosed", async ({ run }) => {
		const client = await DIALS.cleartext();
		await client.close();

		await expect(run(client)).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "ConnectionClosed",
		});
	});

	it("keeps the lifecycle surfaces readable after close", async () => {
		const client = await DIALS.cleartext();
		const capBeforeClose = client.maxConcurrentStreams;

		await client.close();

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

describe("connector options", () => {
	it("applies the symmetric cap from cleartext options", async () => {
		const options = { streams: 3 };
		await using client = await ENGINE.connectCleartext(STACK.muxClearEndpoint, options);

		expect(client.maxConcurrentStreams).toBe(3);
	});
});

describe("cleartext dial readiness", () => {
	it("rejects a dial to a dead endpoint with ConnectionClosed", async () => {
		/*
		 * The discard port: nothing listens there, so the dial closes
		 * before it opens.
		 */
		const deadEndpoint = "ws://127.0.0.1:9";
		await expect(ENGINE.connectCleartext(deadEndpoint)).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "ConnectionClosed",
		});
	});
});
