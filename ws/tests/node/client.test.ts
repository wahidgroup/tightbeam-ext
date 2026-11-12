import { describe, expect, it } from "vitest";

import { Buffer } from "node:buffer";

import type { MuxStreamHandler, TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";
import { Engine } from "@wahidgroup/tightbeam-ws-client";

import { EchoDials } from "../fixtures.js";
import { STACK } from "../stack.js";

/**
 * The client against the real echo servers of the stack: the octets a push
 * sends, how an `await using` scope closes, and the serve claims it reads.
 */

const ENGINE = await Engine.load();

/**
 * The dials of this lane against the echo servers of the stack.
 */
const DIALS = EchoDials.of(ENGINE, STACK);

/**
 * A handler that accepts each stream without a body.
 */
const ACCEPT: MuxStreamHandler = () => undefined;

/*
 * Models an untyped JavaScript caller of a serve: method-syntax members
 * compare bivariant, so the loose claim compiles without assertions.
 */
interface LooseServer {
	serve(handler: MuxStreamHandler, options?: { readonly claim?: unknown }): void;
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
 * A client that an `await using` scope held, once the scope ended.
 */
async function scopedClient(): Promise<ScopedClient> {
	await using client = await DIALS.cleartext();
	const inScope = client.readyState;

	const scoped = { client, inScope };
	return scoped;
}

describe("a push against the duplex echo server", () => {
	it("sends the octets a chunk held at the push, not a later write", async () => {
		await using client = await DIALS.duplex();
		const duplex = client.openDuplex();
		const chunk = run(0xa1);
		const pushed = duplex.push(chunk);

		chunk.fill(0xb2);

		await pushed;
		await duplex.close();

		const echoed = await Array.fromAsync(duplex.body);
		expect(echoed).toEqual([run(0xa1)]);
	});

	it("sends the octets of a chunk whose buffer moves away after the push", async () => {
		await using client = await DIALS.duplex();
		const duplex = client.openDuplex();
		const chunk = run(0xc3);
		const pushed = duplex.push(chunk);

		structuredClone(chunk.buffer, { transfer: [chunk.buffer] });

		await pushed;
		await duplex.close();

		const echoed = await Array.fromAsync(duplex.body);
		expect(echoed).toEqual([run(0xc3)]);
	});

	it("sends the octets a reused Buffer held at each call that waits behind a push", async () => {
		await using client = await DIALS.duplex();
		const duplex = client.openDuplex();
		const chunk = Buffer.alloc(64, 0xa1);
		const first = duplex.push(chunk);
		chunk.fill(0xb2);
		const second = duplex.push(chunk);
		chunk.fill(0xc3);
		const last = duplex.closeWith(chunk);

		chunk.fill(0xd4);

		await Promise.all([first, second, last]);
		const echoed = await Array.fromAsync(duplex.body);
		expect(echoed).toEqual([run(0xa1), run(0xb2), run(0xc3)]);
	});

	it("refuses a chunk whose buffer moved away before the push with InvalidBytes, and the stream still closes", async () => {
		await using client = await DIALS.duplex();
		const duplex = client.openDuplex();
		const chunk = run(0xe5);
		structuredClone(chunk.buffer, { transfer: [chunk.buffer] });

		await expect(duplex.push(chunk)).rejects.toMatchObject({ code: "InvalidBytes" });
		await duplex.closeWith(run(0xf6));

		const echoed = await Array.fromAsync(duplex.body);
		expect(echoed).toEqual([run(0xf6)]);
	});
});

describe("an `await using` client", () => {
	it("closes the client and its socket as the scope ends", async () => {
		const { client, inScope } = await scopedClient();
		expect(inScope).toBe(WebSocket.OPEN);
		expect(client.readyState).toBe(WebSocket.CLOSED);
	});
});

describe("a serve claim", () => {
	it("refuses a claim other than shared or exclusive with InvalidServeClaim", async () => {
		await using client = await DIALS.cleartext();
		const loose: LooseServer = client;
		expect(() => loose.serve(ACCEPT, { claim: "Exclusive" })).toThrow(
			expect.objectContaining({ code: "InvalidServeClaim" }),
		);
	});
});
