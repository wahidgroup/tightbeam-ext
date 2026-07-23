import { describe, expect, it } from "vitest";

import type { ConnectOptions } from "./index.js";
import { TightbeamWsClient } from "./index.js";

/*
 * The connector boundary guards reject before any dial, so the URL and
 * certificates below never leave the process.
 */
const UNREACHED_URL = "ws://127.0.0.1:1";
const UNREACHED_CERT = new Uint8Array(1);
const SCALAR = new Uint8Array(32);

/**
 * Caps the wasm u32 boundary would coerce instead of honoring: negatives
 * wrap, fractions truncate, and zero deadlocks the session.
 */
const COERCIBLE_CAPS = [
	{ label: "a negative cap", cap: -1 },
	{ label: "a zero cap", cap: 0 },
	{ label: "a fractional cap", cap: 2.5 },
	{ label: "a NaN cap", cap: Number.NaN },
	{ label: "an infinite cap", cap: Number.POSITIVE_INFINITY },
	{ label: "a cap beyond u32", cap: 2 ** 32 },
] as const;

/**
 * Every connector that forwards a stream cap to wasm.
 */
const CAPPED_DIALS = [
	{
		name: "connect",
		dial: (cap: number): Promise<TightbeamWsClient> =>
			TightbeamWsClient.connect(UNREACHED_URL, UNREACHED_CERT, {
				maxPeerStreams: cap,
			}),
	},
	{
		name: "connectCleartext",
		dial: (cap: number): Promise<TightbeamWsClient> =>
			TightbeamWsClient.connectCleartext(UNREACHED_URL, { streams: cap }),
	},
	{
		name: "connectMutual",
		dial: (cap: number): Promise<TightbeamWsClient> =>
			TightbeamWsClient.connectMutual(
				UNREACHED_URL,
				UNREACHED_CERT,
				UNREACHED_CERT,
				SCALAR,
				{ maxPeerStreams: cap },
			),
	},
] as const;

describe.each(CAPPED_DIALS)("$name stream cap guard", ({ dial }) => {
	it.each(COERCIBLE_CAPS)(
		"rejects $label with a TypeError",
		async ({ cap }) => {
			const dialed = dial(cap);
			await expect(dialed).rejects.toThrow(TypeError);
			await expect(dialed).rejects.toThrow("stream cap");
		},
	);
});

/*
 * Models an untyped JavaScript caller: method-syntax members compare the
 * bivariant, so the loose signature compiles without assertions.
 */
interface LooseMutualDialer {
	dialMutual(
		url: string,
		serverCertDer: Uint8Array,
		clientCertDer: Uint8Array,
		clientKey: unknown,
		options?: ConnectOptions,
	): Promise<TightbeamWsClient>;
}

const loosely: LooseMutualDialer = {
	dialMutual: TightbeamWsClient.connectMutual,
};

/**
 * Keys that are neither a raw scalar nor signer-shaped. The ArrayBuffer is
 * the WebCrypto `exportKey("raw")` shape callers most plausibly hold.
 */
const FOREIGN_KEYS = [
	{ label: "an ArrayBuffer scalar", key: new ArrayBuffer(32) },
	{
		label: "a signer missing signPrehash",
		key: {
			algorithmOid: "1.2.840.10045.4.3.2",
			publicKeyDer: new Uint8Array(1),
		},
	},
	{
		label: "a signer with a non-string OID",
		key: {
			algorithmOid: 42,
			publicKeyDer: new Uint8Array(1),
			signPrehash: (): Uint8Array => new Uint8Array(64),
		},
	},
	{ label: "a string", key: "not a key" },
] as const;

describe("connectMutual client key guard", () => {
	it.each(FOREIGN_KEYS)(
		"rejects $label with a TypeError",
		async ({ key }) => {
			const dialed = loosely.dialMutual(
				UNREACHED_URL,
				UNREACHED_CERT,
				UNREACHED_CERT,
				key,
			);

			await expect(dialed).rejects.toThrow(TypeError);
			await expect(dialed).rejects.toThrow("clientKey");
		},
	);
});
