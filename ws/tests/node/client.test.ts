import { describe, expect, it } from "vitest";

import type { MuxStreamHandler } from "@wahidgroup/tightbeam-ws-client";
import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";

import { withClient } from "../fixtures.js";
import { STACK } from "../stack.js";

/**
 * The client against the real echo servers of the stack: the octets a push
 * sends, how an `await using` scope closes, and the serve claims it reads.
 */

/**
 * The options of every cleartext dial: the stream cap of the stack, which no
 * handshake negotiates.
 */
const CLEARTEXT = { streams: STACK.streams };

const ENGINE = await TightbeamWsClient.init();

/**
 * The readyState of an open socket.
 */
const OPEN = 1;

/**
 * The readyState of a closed socket.
 */
const CLOSED = 3;

/**
 * A handler that accepts each stream without a body.
 */
const ACCEPT: MuxStreamHandler = () => undefined;

/*
 * Models an untyped JavaScript caller of a serve: method-syntax members
 * compare bivariant, so the loose claim compiles without assertions.
 */
interface LooseServer {
	serve(
		handler: MuxStreamHandler,
		options?: { readonly claim?: unknown },
	): void;
}

/**
 * A client of an `await using` scope, and its readyState inside the scope.
 */
interface ScopedClient {
	readonly client: TightbeamWsClient;
	readonly inScope: number;
}

/**
 * A run of 64 octets of `fill`, as a sent chunk carries it.
 */
function run(fill: number): Uint8Array {
	const octets = new Uint8Array(64).fill(fill);
	return octets;
}

/**
 * Dial the duplex echo server, which answers each chunk with the same octets.
 */
function connectDuplex(): Promise<TightbeamWsClient> {
	const dialing = ENGINE.connectCleartext(STACK.muxDuplexEndpoint, CLEARTEXT);
	return dialing;
}

/**
 * Dial the cleartext echo server.
 */
function connectEcho(): Promise<TightbeamWsClient> {
	const dialing = ENGINE.connectCleartext(STACK.muxClearEndpoint, CLEARTEXT);
	return dialing;
}

/**
 * Every chunk that `body` yields until the peer ends it.
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
 * A client that an `await using` scope held, once the scope ended.
 */
async function scopedClient(): Promise<ScopedClient> {
	await using client = await connectEcho();
	const inScope = client.readyState;

	const scoped = { client, inScope };
	return scoped;
}

describe("a push against the duplex echo server", () => {
	it("sends the octets a chunk held at the push, not a later write", async () => {
		const echoed = await withClient(connectDuplex, async (client) => {
			const duplex = client.openDuplex();
			const chunk = run(0xa1);
			const pushed = duplex.push(chunk);

			chunk.fill(0xb2);

			await pushed;
			await duplex.close();

			const chunks = await collected(duplex.body);
			return chunks;
		});

		expect(echoed).toEqual([run(0xa1)]);
	});

	it("sends the octets of a chunk whose buffer moves away after the push", async () => {
		const echoed = await withClient(connectDuplex, async (client) => {
			const duplex = client.openDuplex();
			const chunk = run(0xc3);
			const pushed = duplex.push(chunk);

			structuredClone(chunk.buffer, { transfer: [chunk.buffer] });

			await pushed;
			await duplex.close();

			const chunks = await collected(duplex.body);
			return chunks;
		});

		expect(echoed).toEqual([run(0xc3)]);
	});
});

describe("an `await using` client", () => {
	it("closes the client and its socket as the scope ends", async () => {
		const { client, inScope } = await scopedClient();
		expect(inScope).toBe(OPEN);
		expect(client.readyState).toBe(CLOSED);
	});
});

describe("a serve claim", () => {
	it("refuses a claim other than shared or exclusive with InvalidServeClaim", async () => {
		await withClient(connectEcho, (client) => {
			const loose: LooseServer = client;
			expect(() => loose.serve(ACCEPT, { claim: "Exclusive" })).toThrow(
				expect.objectContaining({ code: "InvalidServeClaim" }),
			);
			return Promise.resolve();
		});
	});
});
