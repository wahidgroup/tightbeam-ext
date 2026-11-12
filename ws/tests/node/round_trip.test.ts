import { describe, expect, it } from "vitest";

import { Engine } from "@wahidgroup/tightbeam-ws-client";

import { Identities } from "../env.js";
import { EchoDials, NotePayload, SEAL_SECRET } from "../fixtures.js";
import { NobleTransportSigner } from "../signer.js";
import { STACK } from "../stack.js";

const ENGINE = await Engine.load();

/**
 * The dials of this lane against the echo servers of the stack.
 */
const DIALS = EchoDials.of(ENGINE, STACK);

/**
 * The typed body codec for a note: JSON in the profile opaque wrapper.
 */
const NOTES = ENGINE.wrapping(NotePayload);

const TEXT = new TextDecoder();
const BODY = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
const SIGNING_KEY = ENGINE.signingKey(new Uint8Array(32).fill(3));

/**
 * The octets of the salt that hides the message commitment.
 */
const SALT_OCTETS = new Uint8Array(16).fill(0x5a);

/*
 * The frame features under test hold on every transport, so each case dials
 * the cleartext echo server unless it tests a session kind.
 */
describe("Node round-trips against the dockerized echo server", () => {
	it("round-trips a frame over Node's global WebSocket", async () => {
		await using client = await DIALS.cleartext();
		const built = await ENGINE.frameBuilder(BODY).withId("node-e2e").withOrder(3).build();

		const response = await EchoDials.emitOrFail(client, built);
		expect(await response.open(ENGINE.opaque)).toEqual(BODY);
		expect(TEXT.decode(response.id)).toBe("node-e2e");
		expect(response.order).toBe(3n);
	});

	it("verifies a signed, committed frame after the echo", async () => {
		const committed = ENGINE.salt(SALT_OCTETS);
		const salt = ENGINE.salt(SALT_OCTETS);

		await using client = await DIALS.cleartext();
		const built = await ENGINE.frameBuilder(BODY)
			.withId("node-signed")
			.withOrder(4)
			.withMessageHasher(ENGINE.sha3_256, committed)
			.withWitnessHasher(ENGINE.sha3_256)
			.withSigner(SIGNING_KEY)
			.build();

		const response = await EchoDials.emitOrFail(client, built);
		expect(response.signed).toBe(true);

		await response.verify(SIGNING_KEY.verifyingKey());

		await expect(response.frameIntegrityVerdict()).resolves.toBe("verified");
		await expect(response.messageCommitmentVerdict(salt)).resolves.toBe("verified");
	});

	it("round-trips an AES-256-GCM sealed body and opens it with the key", async () => {
		const cipher = ENGINE.aes256Gcm(SEAL_SECRET);

		await using client = await DIALS.cleartext();
		const built = await ENGINE.frameBuilder(BODY).withId("node-aead").withOrder(6).withEncryptor(cipher).build();

		const response = await EchoDials.emitOrFail(client, built);
		expect(response.confidential).toBe(true);
		expect(response.confidentialityInfo?.algorithmOid.toString()).toBe(ENGINE.profile.aes256Gcm.toString());
		expect(response.bodyDer).not.toEqual(BODY);
		await expect(response.open(ENGINE.opaque, { opener: cipher })).resolves.toEqual(BODY);
	});

	it("seals a body to a recipient with HPKE and opens it with the secret", async () => {
		const recipientSecret = new Uint8Array(32).fill(3);
		const recipientPublic = SIGNING_KEY.verifyingKey().toSec1Bytes();

		await using client = await DIALS.cleartext();
		const built = await ENGINE.frameBuilder(BODY)
			.withId("node-hpke")
			.withOrder(8)
			.withEncryptor(ENGINE.hpkeEncryptor(recipientPublic))
			.build();

		const response = await EchoDials.emitOrFail(client, built);
		expect(response.confidential).toBe(true);
		expect(response.bodyDer).not.toEqual(BODY);

		const decryptor = ENGINE.hpkeDecryptor(recipientSecret);
		await expect(response.open(ENGINE.opaque, { opener: decryptor })).resolves.toEqual(BODY);
	});

	it("round-trips a compressed, sealed body and recovers it with the inflator", async () => {
		const zstd = ENGINE.zstd();
		const cipher = ENGINE.aes256Gcm(SEAL_SECRET);

		await using client = await DIALS.cleartext();
		const built = await ENGINE.frameBuilder(BODY)
			.withId("node-packed")
			.withOrder(7)
			.withCompressor(zstd)
			.withEncryptor(cipher)
			.build();

		const response = await EchoDials.emitOrFail(client, built);
		expect(response.compressed).toBe(true);
		expect(response.compactnessInfo?.algorithmOid.toString()).toBe(ENGINE.profile.zstd.toString());

		await expect(
			response.open(ENGINE.opaque, {
				opener: cipher,
				inflator: zstd,
			}),
		).resolves.toEqual(BODY);
	});

	it("round-trips a typed message under a wrapped payload codec", async () => {
		await using client = await DIALS.cleartext();
		const built = await ENGINE.messageBuilder(NOTES, {
			author: "ada",
			text: "hello",
		})
			.withId("node-typed")
			.withOrder(5)
			.build();

		const response = await EchoDials.emitOrFail(client, built);
		expect(await response.open(NOTES)).toEqual({
			author: "ada",
			text: "hello",
		});
	});

	it("resolves undefined when the server accepts without a response frame", async () => {
		await using client = await DIALS.cleartext();
		const built = await ENGINE.frameBuilder(BODY).withId("sink-node").withOrder(10).build();

		const response = await client.emit(built);
		expect(response).toBeUndefined();
	});

	it("round-trips over an HPKE-encrypted session", async () => {
		await using client = await DIALS.encrypted();
		const built = await ENGINE.frameBuilder(BODY).withId("node-secure").withOrder(9).build();

		const response = await EchoDials.emitOrFail(client, built);
		expect(await response.open(ENGINE.opaque)).toEqual(BODY);
		expect(TEXT.decode(response.id)).toBe("node-secure");
	});

	/*
	 * The server pins the client certificate and settles the paywall, so the
	 * completed round trip proves the handshake signed through the signer.
	 */
	it("authenticates mutually through an external transport signer", async () => {
		const signer = new NobleTransportSigner(ENGINE, Identities.stack.bytes("client.key"));

		await using client = await ENGINE.connectMutual(
			STACK.muxMutualEndpoint,
			Identities.stack.demo(signer),
			STACK.dial.paywall.sessionOptions(),
		);
		const built = await ENGINE.frameBuilder(BODY).withId("node-mutual-signer").withOrder(11).build();

		const response = await EchoDials.emitOrFail(client, built);
		expect(await response.open(ENGINE.opaque)).toEqual(BODY);
	});
});
