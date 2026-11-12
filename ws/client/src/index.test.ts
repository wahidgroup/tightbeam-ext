import { describe, expect, expectTypeOf, it } from "vitest";

import { readFileSync } from "node:fs";

import type { MutualConnectOptions, TightbeamWsClient } from "./index.js";
import { Engine } from "./index.js";

const engine = await Engine.load();

/**
 * The octets of the identity fixture `name` under `src/testing`: a server
 * certificate, and a client certificate with its key.
 */
function fixture(name: string): Uint8Array {
	const path = new URL(`./testing/${name}`, import.meta.url);
	const octets = new Uint8Array(readFileSync(path));
	return octets;
}

/*
 * The URL names a closed loopback port, so a dial that passes the connector guards rejects before its handshake.
 */
const UNREACHED_URL = "ws://127.0.0.1:1";
const SERVER_CERT = fixture("server.cert.der");
const CLIENT_CERT = fixture("client.cert.der");
const SCALAR = new Uint8Array(32).fill(1);
const PROFILE_SIGNATURE_OID = "1.2.840.10045.4.3.2";

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
			engine.connect(UNREACHED_URL, SERVER_CERT, {
				maxPeerStreams: cap,
			}),
	},
	{
		name: "connectCleartext",
		dial: (cap: number): Promise<TightbeamWsClient> => engine.connectCleartext(UNREACHED_URL, { streams: cap }),
	},
	{
		name: "connectMutual",
		dial: (cap: number): Promise<TightbeamWsClient> =>
			engine.connectMutual(
				UNREACHED_URL,
				{
					serverCertDer: SERVER_CERT,
					clientCertDer: CLIENT_CERT,
					clientKey: SCALAR,
				},
				{ maxPeerStreams: cap },
			),
	},
] as const;

describe.each(CAPPED_DIALS)("$name stream cap guard", ({ dial }) => {
	it.each(COERCIBLE_CAPS)("rejects $label as an InvalidStreamCap transport error", async ({ cap }) => {
		const dialed = dial(cap);
		await expect(dialed).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "InvalidStreamCap",
		});
	});
});

/*
 * Models an untyped JavaScript caller: method-syntax members compare the
 * bivariant, so the loose signature compiles without assertions.
 */
interface LooseMutualDialer {
	connectMutual(
		url: string,
		identity: {
			readonly serverCertDer: unknown;
			readonly clientCertDer: unknown;
			readonly clientKey: unknown;
		},
		options?: MutualConnectOptions,
	): Promise<TightbeamWsClient>;
}

const loosely: LooseMutualDialer = engine;

/**
 * A signer shape with every member a `TransportSigner` holds.
 */
const SIGNER = {
	algorithmOid: PROFILE_SIGNATURE_OID,
	publicKeyDer: new Uint8Array(1),
	signPrehash: (): Uint8Array => new Uint8Array(64),
};

/**
 * Client keys that are neither a raw scalar nor a whole signer, and the code
 * each refusal carries. The ArrayBuffer is the WebCrypto `exportKey("raw")`
 * shape callers most plausibly hold.
 */
const FOREIGN_KEYS = [
	{
		label: "an ArrayBuffer scalar",
		key: new ArrayBuffer(32),
		code: "InvalidCallback",
	},
	{
		label: "a scalar of 31 octets",
		key: new Uint8Array(31).fill(1),
		code: "InvalidSigningKey",
	},
	{
		label: "a signer missing signPrehash",
		key: { ...SIGNER, signPrehash: undefined },
		code: "InvalidCallback",
	},
	{
		label: "a signer missing publicKeyDer",
		key: { ...SIGNER, publicKeyDer: undefined },
		code: "InvalidBytes",
	},
	{
		label: "a signer whose publicKeyDer is an array",
		key: { ...SIGNER, publicKeyDer: [1, 2, 3] },
		code: "InvalidBytes",
	},
	{
		label: "a signer whose publicKeyDer is an ArrayBuffer",
		key: { ...SIGNER, publicKeyDer: new ArrayBuffer(3) },
		code: "InvalidBytes",
	},
	{
		label: "a signer with a non-string OID",
		key: { ...SIGNER, algorithmOid: 42 },
		code: "InvalidOid",
	},
	{ label: "a string", key: "not a key", code: "InvalidClientKey" },
] as const;

describe("connectMutual client key guard", () => {
	it.each(FOREIGN_KEYS)("rejects $label with the code $code", async ({ key, code }) => {
		const dialed = loosely.connectMutual(UNREACHED_URL, {
			serverCertDer: SERVER_CERT,
			clientCertDer: CLIENT_CERT,
			clientKey: key,
		});

		await expect(dialed).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code,
		});
	});
});

describe("connectMutual certificate guard", () => {
	it("rejects a numeric certificate as an InvalidBytes transport error", async () => {
		const dialed = loosely.connectMutual(UNREACHED_URL, {
			serverCertDer: 7,
			clientCertDer: CLIENT_CERT,
			clientKey: SCALAR,
		});

		await expect(dialed).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "InvalidBytes",
		});
	});

	it.each([
		{
			name: "connect",
			dial: (): Promise<TightbeamWsClient> => engine.connect(UNREACHED_URL, new Uint8Array(1)),
			path: "serverCertDer",
		},
		{
			name: "connectMutual",
			dial: (): Promise<TightbeamWsClient> =>
				engine.connectMutual(UNREACHED_URL, {
					serverCertDer: SERVER_CERT,
					clientCertDer: new Uint8Array(1),
					clientKey: SCALAR,
				}),
			path: "identity.clientCertDer",
		},
	])("$name refuses octets that are no certificate before any dial", async ({ dial, path }) => {
		await expect(dial()).rejects.toMatchObject({
			code: "InvalidCertificate",
			path,
		});
	});
});

describe("connectMutual identity read", () => {
	it("reads the key before the call returns, so a later write is not dialed", async () => {
		/*
		 * The identity is whole at the call, and its scalar is zero after it.
		 * A read at the call pairs the certificate with its key, so the dial
		 * fails only at the handshake, whose socket nothing answers. A later
		 * read would refuse the zero scalar with `InvalidSigningKey`.
		 */
		const key = fixture("client.key");
		const dialed = engine.connectMutual(UNREACHED_URL, {
			serverCertDer: fixture("server.cert.der"),
			clientCertDer: fixture("client.cert.der"),
			clientKey: key,
		});
		key.fill(0);

		await expect(dialed).rejects.toMatchObject({
			code: "PeerClosedBeforeHandshake",
		});
	});
});

describe("session offer mutual-only guard", () => {
	it("rejects budgets an untyped caller passes to connect", async () => {
		const budgets = { clientToServer: 1, serverToClient: 1 };
		const dialed = engine.connect(
			UNREACHED_URL,
			SERVER_CERT,
			// @ts-expect-error A mutual-only field fails at runtime.
			{ budgets },
		);
		await expect(dialed).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "SessionOfferRequiresMutual",
		});
	});

	it("rejects approveReceipt on connectCleartext", async () => {
		const approveReceipt = (): Uint8Array => new Uint8Array(1);
		const dialed = engine.connectCleartext(
			UNREACHED_URL,
			// @ts-expect-error A mutual-only field fails at runtime.
			{ approveReceipt },
		);
		await expect(dialed).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code: "SessionOfferRequiresMutual",
		});
	});
});

/**
 * The reason {@link TightbeamWsClient.shutdownWith} takes.
 */
type ShutdownReason = Parameters<TightbeamWsClient["shutdownWith"]>[0];

describe("shutdownWith reason", () => {
	it("refuses the bare application label at compile time", () => {
		expectTypeOf<"application">().not.toExtend<ShutdownReason>();
	});
});
