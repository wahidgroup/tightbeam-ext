import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha3_256, sha3_512 } from "@noble/hashes/sha3.js";
import { assert, describe, expect, it } from "vitest";

import type { Version } from "#wasm";

import type { Aes256Gcm, BodyDecryptor, BodyEncryptor, EncryptedBody, Hasher } from "./crypto.js";
import type { Frame, FrameBuilder, MessageCodec } from "./index.js";
import type { Note } from "./testing/notes.js";
import type { OidName } from "./views.js";
import { Engine } from "./index.js";
import { NotePayload } from "./testing/notes.js";
import { PromptedSigner } from "./testing/prompted_signer.js";
import { ZlibCompression } from "./testing/zlib.js";
import { NobleFrameVerifier, NobleSignatory } from "./testing/noble_signatory.js";

/**
 * Wasm-backed round-trips through the real codec: what the builder writes,
 * `Frame` must read back, with the profile algorithms and with
 * caller-supplied (noble-backed) ones.
 */

const engine = await Engine.load();
const Notes = engine.wrapping(NotePayload);

const BODY = new Uint8Array([1, 2, 3, 4]);
const SIGNING_KEY = engine.signingKey(new Uint8Array(32).fill(1));
const AES_KEY = new Uint8Array(32).fill(7);
const KEY_ID = new TextEncoder().encode("tbws/test/kek/v1");

/**
 * An encryptor whose ciphertext is one DER value, an empty OCTET STRING, so
 * the carried body parses as DER although the frame is sealed. A profile
 * ciphertext parses as DER only by chance.
 */
const DER_CIPHERTEXT: BodyEncryptor = {
	encrypt: async (bodyDer: Uint8Array, contentOid: OidName) => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const sealed = await cipher.encrypt(bodyDer, contentOid);

		const ciphertext = new Uint8Array([0x04, 0x00]);
		const derCiphertext = { ...sealed, ciphertext };
		return derCiphertext;
	},
};

/**
 * The SHA3-512 OID, an algorithm outside the tightbeam profile.
 */
const SHA3_512_OID = "2.16.840.1.101.3.4.2.10";

/**
 * A codec whose message is the body DER itself, the way a schema codec may
 * hand back the bytes it validated.
 */
const RAW_BODY: MessageCodec<Uint8Array> = {
	encode: (bodyDer) => bodyDer,
	decode: (bodyDer) => bodyDer,
};

/**
 * A {@link Hasher} backed by an independent JavaScript digest (noble),
 * standing in for any bring-your-own hash library.
 */
class NobleHasher implements Hasher {
	constructor(
		readonly algorithmOid: OidName,
		private readonly hash: (data: Uint8Array) => Uint8Array,
	) {}

	digest(data: Uint8Array): Promise<Uint8Array> {
		const digest = this.hash(data);
		const result = Promise.resolve(digest);
		return result;
	}
}

/**
 * The plain-digest salt, which a frame committed without a salt verifies
 * under.
 */
const EMPTY_SALT = engine.salt(new Uint8Array());

describe("Engine.frame", () => {
	it("refuses bytes that are no frame at construction", () => {
		expect(() => engine.frame(new Uint8Array([1, 2, 3]))).toThrow(
			expect.objectContaining({ code: "SerializationError" }),
		);
	});

	it("keeps its own copy of the DER it parses", async () => {
		const built = await engine.frameBuilder(BODY).withId("copy-in").build();
		const received = built.toDer();
		const parsed = engine.frame(received);

		received.fill(0);

		expect(parsed.toDer()).toEqual(built.toDer());
	});
});

describe("Frame.toDer", () => {
	it("hands out a copy, so a write to it leaves the frame unchanged", async () => {
		const built = await engine.frameBuilder(BODY).withId("copy-out").build();

		const handed = built.toDer();
		handed.fill(0);
		expect(built.toDer()).not.toEqual(handed);
	});
});

describe("Frame byte getters", () => {
	it("hand out the body as a copy, so a write to it leaves open unchanged", async () => {
		const built = await engine.frameBuilder(BODY).withId("body-out").build();

		const handed = built.bodyDer;
		handed.fill(0);

		const opened = await built.open(engine.opaque);
		expect(opened).toEqual(BODY);
	});

	it("hand out the opened body as a copy, so a write to it leaves the next open unchanged", async () => {
		const cleartextBodyDer = engine.opaque.encode(BODY);
		const built = await engine.frameBuilder(BODY).withId("opened-out").build();

		const handed = await built.open(RAW_BODY);
		handed.fill(0);

		const opened = await built.open(RAW_BODY);
		expect(opened).toEqual(cleartextBodyDer);
	});

	it("hand out the sealing envelope as a copy, so a write to it leaves open unchanged", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const built = await engine.frameBuilder(BODY).withId("frame").withEncryptor(cipher).build();

		const sealing = built.confidentialityInfo;
		const handed = sealing?.envelopeDer ?? new Uint8Array();

		handed.fill(0);

		const opened = await built.open(engine.opaque, { opener: cipher });
		expect(opened).toEqual(BODY);
	});

	it("hand out the commitment digest as a copy, so a write to it leaves the verdict unchanged", async () => {
		const committed = await engine.frameBuilder(BODY).withId("frame").withMessageHasher(engine.sha3_256).build();

		const commitment = committed.messageIntegrityInfo;
		const handed = commitment?.digest ?? new Uint8Array();
		handed.fill(0);

		const verdict = await committed.messageCommitmentVerdict(EMPTY_SALT);
		expect(verdict).toBe("verified");
	});

	it("hand out the id as a copy", async () => {
		const built = await engine.frameBuilder(BODY).withId("id-out").build();
		const handed = built.id;
		handed.fill(0);
		expect(built.id).not.toEqual(handed);
	});

	it("hand out the signature as a copy", async () => {
		const built = await engine.frameBuilder(BODY).withId("frame").withSigner(SIGNING_KEY).build();

		const handed = built.signatureInfo?.signature ?? new Uint8Array();
		handed.fill(0);

		expect(built.signatureInfo?.signature).not.toEqual(handed);
	});

	it("hand out the matrix as a copy", async () => {
		const matrix = new Uint8Array([0, 1, 1, 0]);
		const built = await engine.frameBuilder(BODY).withId("frame").withMatrix(2, matrix).build();

		const handed = built.matrix?.data ?? new Uint8Array();
		handed.fill(0);

		expect(built.matrix?.data).not.toEqual(handed);
	});
});

describe("Frame metadata round-trip", () => {
	it("reads back a cleartext V0 frame", async () => {
		const expectedId = new TextEncoder().encode("clear-1");
		const built = await engine.frameBuilder(BODY).withId("clear-1").withOrder(7).build();
		expect(built.version).toBe(engine.Version.V0);
		expect(built.id).toEqual(expectedId);
		expect(built.order).toBe(7n);
		expect(await built.open(engine.opaque)).toEqual(BODY);
		expect(built.signed).toBe(false);
		expect(built.messageIntegrity).toBe(false);
		expect(built.frameIntegrity).toBe(false);
		expect(built.confidential).toBe(false);
		expect(built.priority).toBeUndefined();
		expect(built.lifetime).toBeUndefined();
		expect(built.previousFrame).toBeUndefined();
		expect(built.matrix).toBeUndefined();
	});

	it("reads back V2 metadata and a V3 matrix", async () => {
		const digest = new Uint8Array(32).fill(0xaa);
		const matrix = new Uint8Array([0, 1, 1, 0]);

		const built = await engine
			.frameBuilder(BODY)
			.withId("rich")
			.withOrder(21)
			.withPriority(engine.MessagePriority.Expedited)
			.withLifetime(300)
			.withPreviousHash(engine.digestInfo(engine.oid(SHA3_512_OID), digest))
			.withMatrix(2, matrix)
			.build();
		expect(built.version).toBe(engine.Version.V3);
		expect(built.priority).toBe(engine.MessagePriority.Expedited);
		expect(built.lifetime).toBe(300n);
		expect(built.previousFrame?.algorithmOid.toString()).toBe(SHA3_512_OID);
		expect(built.previousFrame?.digest).toEqual(digest);
		expect(built.matrix?.n).toBe(2);
		expect(built.matrix?.data).toEqual(matrix);
	});

	it("honors a matching version assertion against the real codec", async () => {
		const built = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withSigner(SIGNING_KEY)
			.assertVersion(engine.Version.V1)
			.build();
		expect(built.version).toBe(engine.Version.V1);
	});
});

describe("Framed (frame-in-frame)", () => {
	/**
	 * A signed application frame carried through a wrapper body, the way
	 * a pub/sub update relays it.
	 */
	async function relayed(): Promise<{ inner: Frame; relay: Frame }> {
		const inner = await engine
			.frameBuilder(BODY)
			.withId("order-42")
			.withOrder(7)
			.withPriority(engine.MessagePriority.Expedited)
			.withLifetime(60)
			.withSigner(SIGNING_KEY)
			.build();

		const wrapper = await engine.messageBuilder(engine.framed, inner).withId("orders").withOrder(1).build();

		const relay = await wrapper.open(engine.framed);
		return { inner, relay };
	}

	it("relays the inner frame byte-for-byte", async () => {
		const { inner, relay } = await relayed();
		expect(relay.toDer()).toEqual(inner.toDer());
	});

	it("keeps the inner frame verifiable after the trip", async () => {
		const { relay } = await relayed();
		await expect(relay.verify(SIGNING_KEY.verifyingKey())).resolves.toBeUndefined();
	});

	it("keeps the application metadata readable after the trip", async () => {
		const { relay } = await relayed();
		expect(relay.id).toEqual(new TextEncoder().encode("order-42"));
		expect(relay.order).toBe(7n);
		expect(relay.priority).toBe(engine.MessagePriority.Expedited);
		expect(relay.lifetime).toBe(60n);
		expect(await relay.open(engine.opaque)).toEqual(BODY);
	});
});

describe("the engine decides the version floor", () => {
	interface FloorCase {
		field: string;
		expected: Version;
		make: () => FrameBuilder;
	}

	const aeadEncryptor = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
	const recipientPublic = SIGNING_KEY.verifyingKey().toSec1Bytes();
	const hpkeEncryptor = engine.hpkeEncryptor(recipientPublic);

	const cases: FloorCase[] = [
		{
			field: "bare payload",
			expected: engine.Version.V0,
			make: () => engine.frameBuilder(BODY),
		},
		{
			field: "signer",
			expected: engine.Version.V1,
			make: () => engine.frameBuilder(BODY).withSigner(SIGNING_KEY),
		},
		{
			field: "aead encryptor",
			expected: engine.Version.V1,
			make: () => engine.frameBuilder(BODY).withEncryptor(aeadEncryptor),
		},
		{
			field: "hpke encryptor",
			expected: engine.Version.V1,
			make: () => engine.frameBuilder(BODY).withEncryptor(hpkeEncryptor),
		},
		{
			field: "priority",
			expected: engine.Version.V2,
			make: () => engine.frameBuilder(BODY).withPriority(engine.MessagePriority.Standard),
		},
		{
			field: "lifetime",
			expected: engine.Version.V2,
			make: () => engine.frameBuilder(BODY).withLifetime(60),
		},
		{
			field: "previous hash",
			expected: engine.Version.V2,
			make: () =>
				engine
					.frameBuilder(BODY)
					.withPreviousHash(engine.digestInfo(engine.profile.sha3_256, new Uint8Array(32).fill(1))),
		},
		{
			field: "message hasher",
			expected: engine.Version.V1,
			make: () => engine.frameBuilder(BODY).withMessageHasher(engine.sha3_256),
		},
		{
			field: "witness hasher",
			expected: engine.Version.V1,
			make: () => engine.frameBuilder(BODY).withWitnessHasher(engine.sha3_256),
		},
		{
			field: "signer and priority",
			expected: engine.Version.V2,
			make: () => engine.frameBuilder(BODY).withSigner(SIGNING_KEY).withPriority(engine.MessagePriority.Standard),
		},
		{
			field: "matrix",
			expected: engine.Version.V3,
			make: () => engine.frameBuilder(BODY).withMatrix(2, new Uint8Array([0, 1, 1, 0])),
		},
	];

	it.each(cases)("derives V$expected for $field from GatedField::since", async ({ expected, make }) => {
		const built = await make().withId("floor").assertVersion(expected).build();
		expect(built.version).toBe(expected);
	});
});

describe("Frame.verify", () => {
	it("verifies a locally signed frame with the derived key", async () => {
		const built = await engine.frameBuilder(BODY).withId("signed").withOrder(1).withSigner(SIGNING_KEY).build();
		expect(built.signed).toBe(true);
		expect(built.signatureInfo?.algorithmOid.toString()).toBe(engine.profile.ecdsaWithSha3_256.toString());
		expect(built.signatureInfo?.digestAlgorithmOid.toString()).toBe(engine.profile.sha3_256.toString());
		await expect(built.verify(SIGNING_KEY.verifyingKey())).resolves.toBeUndefined();
	});

	it("rejects verification under the wrong key", async () => {
		const other = engine.signingKey(new Uint8Array(32).fill(2));
		const otherKey = other.verifyingKey();

		const signed = await engine.frameBuilder(BODY).withId("frame").withSigner(SIGNING_KEY).build();
		await expect(signed.verify(otherKey)).rejects.toThrow();
	});

	it("rejects verification of an unsigned frame", async () => {
		const unsigned = await engine.frameBuilder(BODY).withId("frame").build();
		await expect(unsigned.verify(SIGNING_KEY.verifyingKey())).rejects.toThrow();
	});

	it("verifies a profile signature externally from its prehash and signatureInfo", async () => {
		const built = await engine.frameBuilder(BODY).withId("frame").withSigner(SIGNING_KEY).build();

		const info = built.signatureInfo;
		expect(info?.algorithmOid.toString()).toBe(engine.profile.ecdsaWithSha3_256.toString());

		const signature = info?.signature ?? new Uint8Array();
		const publicKey = SIGNING_KEY.verifyingKey().toSec1Bytes();
		const valid = secp256k1.verify(signature, built.signaturePrehash(), publicKey, {
			format: "der",
			prehash: false,
		});
		expect(valid).toBe(true);
	});
});

describe("Frame preimages", () => {
	it("an unsigned frame refuses its prehash as the engine does and still reads its witness", async () => {
		const unsigned = await engine.frameBuilder(BODY).withId("frame").withWitnessHasher(engine.sha3_256).build();
		const missing = expect.objectContaining({ code: "MissingSignature" });

		expect(() => unsigned.signaturePrehash()).toThrow(missing);
		await expect(unsigned.frameIntegrityVerdict()).resolves.toBe("verified");
	});
});

describe("Frame.frameIntegrityVerdict", () => {
	it.each([
		{ name: "profile SHA3-256", hasher: engine.sha3_256 },
		{
			name: "noble SHA3-512 (bring-your-own)",
			hasher: new NobleHasher(engine.oid(SHA3_512_OID), sha3_512),
		},
	])("reports verified under the matching $name hasher", async ({ hasher }) => {
		const witnessed = await engine.frameBuilder(BODY).withId("frame").withWitnessHasher(hasher).build();

		await expect(witnessed.frameIntegrityVerdict(hasher)).resolves.toBe("verified");
	});

	it("reports absent for an unwitnessed frame", async () => {
		const bare = await engine.frameBuilder(BODY).withId("frame").build();
		await expect(bare.frameIntegrityVerdict()).resolves.toBe("absent");
	});

	it("reports algorithm-mismatch when checked under the wrong hasher", async () => {
		const nobleSha3_512 = new NobleHasher(engine.oid(SHA3_512_OID), sha3_512);

		const profileHasher = engine.sha3_256;
		const witnessed = await engine.frameBuilder(BODY).withId("frame").withWitnessHasher(nobleSha3_512).build();

		await expect(witnessed.frameIntegrityVerdict(profileHasher)).resolves.toBe("algorithm-mismatch");
	});

	it("agrees across implementations of the same algorithm", async () => {
		const nobleSha3_256 = new NobleHasher(engine.profile.sha3_256, sha3_256);

		const profileHasher = engine.sha3_256;
		const witnessed = await engine.frameBuilder(BODY).withId("frame").withWitnessHasher(nobleSha3_256).build();

		await expect(witnessed.frameIntegrityVerdict(profileHasher)).resolves.toBe("verified");
	});
});

describe("Frame.messageCommitmentVerdict", () => {
	const SALT_OCTETS = new TextEncoder().encode("commitment-salt-value");
	const SALT = engine.salt(SALT_OCTETS);

	it("reports verified for the disclosed salt", async () => {
		const committed = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withMessageHasher(engine.sha3_256, engine.salt(SALT_OCTETS))
			.build();

		await expect(committed.messageCommitmentVerdict(SALT)).resolves.toBe("verified");
	});

	it("reports mismatch for the wrong salt", async () => {
		const wrongSalt = engine.salt(new TextEncoder().encode("the-wrong-salt-value"));

		const committed = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withMessageHasher(engine.sha3_256, engine.salt(SALT_OCTETS))
			.build();

		await expect(committed.messageCommitmentVerdict(wrongSalt)).resolves.toBe("mismatch");
	});

	it("reports absent for a frame without a commitment", async () => {
		const bare = await engine.frameBuilder(BODY).withId("frame").build();
		await expect(bare.messageCommitmentVerdict(SALT)).resolves.toBe("absent");
	});

	it("refuses a sealed frame whose ciphertext parses as one DER value", async () => {
		const sealed = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withMessageHasher(engine.sha3_256, engine.salt(SALT_OCTETS))
			.withEncryptor(DER_CIPHERTEXT)
			.build();

		await expect(sealed.messageCommitmentVerdict(SALT)).rejects.toThrow(
			expect.objectContaining({ code: "OpaqueBody", layer: "opener" }),
		);
	});

	it("verifies the commitment of a sealed and compressed frame through the opening of its opened body DER", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const zstd = engine.zstd();
		const sealed = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withMessageHasher(engine.sha3_256, engine.salt(SALT_OCTETS))
			.withCompressor(zstd)
			.withEncryptor(cipher)
			.build();

		const bodyDer = await sealed.open(RAW_BODY, { opener: cipher, inflator: zstd });
		const commitment = sealed.messageIntegrityInfo;
		assert.isDefined(commitment);
		const opening = engine.opening(engine.salt(SALT_OCTETS), bodyDer);

		await expect(opening.verify(engine.sha3_256, commitment)).resolves.toBe(true);
	});
});

describe("external Signatory across the wasm boundary", () => {
	const EXTERNAL_SECRET = new Uint8Array(32).fill(5);

	it("attaches a noble-produced signature that wasm verification accepts", async () => {
		const signatory = new NobleSignatory(engine, EXTERNAL_SECRET);
		const built = await engine.frameBuilder(BODY).withId("external").withOrder(11).withSigner(signatory).build();
		expect(built.signed).toBe(true);

		const verifyingKey = engine.verifyingKey(signatory.publicKey());
		await expect(built.verify(verifyingKey)).resolves.toBeUndefined();
	});

	it("verifies through the signatory's BYO FrameVerifier", async () => {
		const signatory = new NobleSignatory(engine, EXTERNAL_SECRET);
		const built = await engine.frameBuilder(BODY).withId("frame").withSigner(signatory).build();
		await expect(built.verify(signatory.verifier)).resolves.toBeUndefined();
	});

	it("rejects a BYO FrameVerifier under the wrong public key", async () => {
		const signatory = new NobleSignatory(engine, EXTERNAL_SECRET);
		const built = await engine.frameBuilder(BODY).withId("frame").withSigner(signatory).build();
		const wrongKey = secp256k1.getPublicKey(new Uint8Array(32).fill(9), true);

		const wrong = new NobleFrameVerifier(engine, wrongKey);
		await expect(built.verify(wrong)).rejects.toThrow();
	});

	it("rejects verification of the external signature under another key", async () => {
		const signatory = new NobleSignatory(engine, EXTERNAL_SECRET);
		const built = await engine.frameBuilder(BODY).withId("frame").withSigner(signatory).build();
		await expect(built.verify(SIGNING_KEY.verifyingKey())).rejects.toThrow();
	});

	it("refuses a released signing key with its code", async () => {
		const released = engine.signingKey(new Uint8Array(32).fill(9));
		released[Symbol.dispose]();

		const attempt = engine.frameBuilder(BODY).withId("frame").withSigner(released).build();
		await expect(attempt).rejects.toMatchObject({ code: "KeyReleased" });
	});

	it("refuses a version mismatch before the signatory acts", async () => {
		const declining = new PromptedSigner(SIGNING_KEY);

		const building = engine
			.frameBuilder(BODY)
			.withId("frame")
			.withSigner(declining)
			.assertVersion(engine.Version.V0)
			.build();
		await expect(building).rejects.toMatchObject({
			code: "VersionMismatch",
		});
	});
});

describe("Frame.open of a sealed body", () => {
	it("round-trips an AES-256-GCM sealed body", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const cleartextBodyDer = engine.opaque.encode(BODY);

		const built = await engine.frameBuilder(BODY).withId("frame").withEncryptor(cipher).build();
		expect(built.confidential).toBe(true);
		expect(built.confidentialityInfo?.algorithmOid.toString()).toBe(engine.profile.aes256Gcm.toString());
		expect(built.bodyDer).not.toEqual(cleartextBodyDer);

		await expect(built.open(engine.opaque, { opener: cipher })).resolves.toEqual(BODY);
	});

	it("rejects the wrong AEAD key", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const wrongKey = new Uint8Array(32).fill(9);
		const wrong = engine.aes256Gcm({ key: wrongKey, keyId: KEY_ID });

		const built = await engine.frameBuilder(BODY).withId("frame").withEncryptor(cipher).build();
		await expect(built.open(engine.opaque, { opener: wrong })).rejects.toThrow();
	});

	it("round-trips an HPKE body sealed to a recipient", async () => {
		const recipientSecret = new Uint8Array(32).fill(1);
		const recipientPublic = SIGNING_KEY.verifyingKey().toSec1Bytes();
		const encryptor = engine.hpkeEncryptor(recipientPublic);
		const cleartextBodyDer = engine.opaque.encode(BODY);

		const built = await engine.frameBuilder(BODY).withId("frame").withEncryptor(encryptor).build();
		expect(built.confidential).toBe(true);
		expect(built.confidentialityInfo?.algorithmOid.toString()).toBe(engine.profile.aes256Gcm.toString());
		expect(built.bodyDer).not.toEqual(cleartextBodyDer);

		const decryptor = engine.hpkeDecryptor(recipientSecret);
		await expect(built.open(engine.opaque, { opener: decryptor })).resolves.toEqual(BODY);
	});

	it("rejects the wrong HPKE secret", async () => {
		const recipientPublic = SIGNING_KEY.verifyingKey().toSec1Bytes();
		const encryptor = engine.hpkeEncryptor(recipientPublic);
		const built = await engine.frameBuilder(BODY).withId("frame").withEncryptor(encryptor).build();

		const wrongSecret = new Uint8Array(32).fill(2);
		const wrong = engine.hpkeDecryptor(wrongSecret);
		await expect(built.open(engine.opaque, { opener: wrong })).rejects.toThrow();
	});

	it("opens a cleartext frame under any options", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const cleartext = await engine.frameBuilder(BODY).withId("frame").build();

		await expect(cleartext.open(engine.opaque, { opener: cipher })).resolves.toEqual(BODY);
	});
});

describe("Frame.open", () => {
	/**
	 * A key other than {@link AES_KEY}, under the same identifier, whose open
	 * of the seal fails.
	 */
	const WRONG_KEY = new Uint8Array(32).fill(8);

	/**
	 * A zlib compression of the platform, which the profile inflator refuses.
	 */
	const ZLIB = new ZlibCompression(engine);

	it("opens a sealed and compressed body with named capabilities", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const zstd = engine.zstd();
		const built = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withCompressor(zstd)
			.withEncryptor(cipher)
			.build();

		const opened = built.open(engine.opaque, {
			opener: cipher,
			inflator: zstd,
		});
		await expect(opened).resolves.toEqual(BODY);
	});

	it("refuses compactness the inflator does not admit before any decryption", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const opener = engine.aes256Gcm({ key: WRONG_KEY, keyId: KEY_ID });
		const built = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withCompressor(ZLIB)
			.withEncryptor(cipher)
			.build();

		const opened = built.open(engine.opaque, {
			opener,
			inflator: engine.zstd(),
		});
		await expect(opened).rejects.toMatchObject({
			code: "CompactnessRefused",
		});
	});

	it("refuses a sealed body without an opener", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const built = await engine.frameBuilder(BODY).withId("frame").withEncryptor(cipher).build();

		await expect(built.open(engine.opaque)).rejects.toMatchObject({
			code: "OpaqueBody",
			layer: "opener",
		});
	});

	it.each([
		{
			kind: "sealed",
			layer: "opener",
			layered: (begun: FrameBuilder<true>): FrameBuilder<true> =>
				begun.withEncryptor(engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID })),
		},
		{
			kind: "compressed",
			layer: "inflator",
			layered: (begun: FrameBuilder<true>): FrameBuilder<true> => begun.withCompressor(engine.zstd()),
		},
	])("refuses one $kind body with one code on every read", async ({ kind, layer, layered }) => {
		const begun = engine.frameBuilder(BODY).withId(kind);
		const built = await layered(begun).build();

		const refusal = { code: "OpaqueBody", layer };
		await expect(built.open(engine.opaque)).rejects.toMatchObject(refusal);
		expect(() => built.commitmentInput(EMPTY_SALT)).toThrow(expect.objectContaining(refusal));
	});
});

describe("bring-your-own encryption across the wasm boundary", () => {
	/**
	 * A {@link BodyEncryptor} and {@link BodyDecryptor} outside the wasm
	 * profile classes: it hands the codec a finished envelope, which a user
	 * implementation of the public port builds with its own scheme.
	 */
	class ForwardingCipher implements BodyEncryptor, BodyDecryptor {
		constructor(private readonly cipher: Aes256Gcm) {}

		encrypt(bodyDer: Uint8Array, contentOid: OidName): Promise<EncryptedBody> {
			return this.cipher.encrypt(bodyDer, contentOid);
		}

		decrypt(sealed: EncryptedBody): Promise<Uint8Array> {
			return this.cipher.decrypt(sealed);
		}
	}

	it("installs the envelope a caller-supplied encryptor returns", async () => {
		const encryptor = new ForwardingCipher(engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID }));
		const built = await engine.frameBuilder(BODY).withId("frame").withEncryptor(encryptor).build();
		expect(built.confidentialityInfo?.algorithmOid.toString()).toBe(engine.profile.aes256Gcm.toString());
		expect(built.confidentialityInfo?.contentOid.toString()).toBe(engine.profile.data.toString());

		const decryptor = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		await expect(built.open(engine.opaque, { opener: decryptor })).resolves.toEqual(BODY);
	});

	it("seals the body as the content type the builder names", async () => {
		const contentOid = "1.2.840.113549.1.7.2";
		const encryptor = new ForwardingCipher(engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID }));
		const built = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withContentOid(engine.oid(contentOid))
			.withEncryptor(encryptor)
			.build();
		expect(built.confidentialityInfo?.contentOid.toString()).toBe(contentOid);

		await expect(built.open(engine.opaque, { opener: encryptor })).resolves.toEqual(BODY);
	});

	it("refuses bytes that are no envelope", async () => {
		const forged: BodyEncryptor = {
			encrypt: (bodyDer: Uint8Array): Promise<EncryptedBody> =>
				Promise.resolve({
					envelopeDer: new Uint8Array([0x30, 0x00]),
					ciphertext: bodyDer,
				}),
		};

		await expect(engine.frameBuilder(BODY).withId("frame").withEncryptor(forged).build()).rejects.toThrow();
	});
});

describe("bring-your-own compression", () => {
	const zlib = new ZlibCompression(engine);

	it("round-trips a compressed cleartext body", async () => {
		const uncompressedBodyDer = engine.opaque.encode(BODY);

		const built = await engine.frameBuilder(BODY).withId("frame").withCompressor(zlib).build();
		expect(built.compressed).toBe(true);
		expect(built.compactnessInfo?.algorithmOid.toString()).toBe(engine.profile.zlib.toString());
		expect(built.compactnessInfo?.contentOid.toString()).toBe(engine.profile.data.toString());
		expect(built.bodyDer).not.toEqual(uncompressedBodyDer);

		const opened = built.open(engine.opaque, { inflator: zlib });
		await expect(opened).resolves.toEqual(BODY);
	});

	it("round-trips a compressed-then-sealed body", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const built = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withCompressor(zlib)
			.withEncryptor(cipher)
			.build();

		expect(built.compressed).toBe(true);
		expect(built.confidential).toBe(true);
		await expect(built.open(engine.opaque, { opener: cipher, inflator: zlib })).resolves.toEqual(BODY);
	});

	it("rejects decryption of a compressed body without an inflator", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const built = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withCompressor(zlib)
			.withEncryptor(cipher)
			.build();

		await expect(built.open(engine.opaque, { opener: cipher })).rejects.toMatchObject({
			code: "OpaqueBody",
			layer: "inflator",
		});
	});

	it("rejects a read of a compressed body without an inflator", async () => {
		const built = await engine.frameBuilder(BODY).withId("frame").withCompressor(zlib).build();
		await expect(built.open(engine.opaque)).rejects.toMatchObject({
			code: "OpaqueBody",
			layer: "inflator",
		});
	});

	it("refuses a body that names another algorithm than the inflator", async () => {
		const built = await engine.frameBuilder(BODY).withId("frame").withCompressor(zlib).build();

		const opened = built.open(engine.opaque, { inflator: engine.zstd() });
		await expect(opened).rejects.toMatchObject({
			code: "CompactnessRefused",
		});
	});

	it("commits to the uncompressed body, so a compressed frame refuses the check until inflated", async () => {
		const built = await engine
			.frameBuilder(BODY)
			.withId("frame")
			.withMessageHasher(engine.sha3_256)
			.withCompressor(zlib)
			.build();

		await expect(built.messageCommitmentVerdict(EMPTY_SALT)).rejects.toMatchObject({
			code: "OpaqueBody",
			layer: "inflator",
		});

		const bodyDer = await built.open(engine.opaque, { inflator: zlib });
		expect(bodyDer).toEqual(BODY);
	});
});

describe("typed message codecs", () => {
	/**
	 * A full-DER codec for `SEQUENCE { title UTF8String }`, the schema of
	 * the Rust `Doc` interop test: no opaque wrapper, so a typed Rust peer
	 * decodes the body directly.
	 */
	const Doc: MessageCodec<{ title: string }> = {
		encode(message: { title: string }): Uint8Array {
			const title = new TextEncoder().encode(message.title);
			const bodyDer = new Uint8Array([0x30, title.length + 2, 0x0c, title.length, ...title]);
			return bodyDer;
		},
		decode(bodyDer: Uint8Array): { title: string } {
			const length = bodyDer[3] ?? 0;
			if (bodyDer[0] !== 0x30 || bodyDer[2] !== 0x0c || bodyDer.length !== length + 4) {
				throw new TypeError("Not a Doc body");
			}

			const title = new TextDecoder().decode(bodyDer.slice(4));
			return { title };
		},
	};

	const NOTE: Note = { author: "ada", text: "hello" };

	it("round-trips a wrapped typed message", async () => {
		const built = await engine.messageBuilder(Notes, NOTE).withId("frame").build();
		expect(await built.open(Notes)).toEqual(NOTE);
	});

	it("round-trips a wrapped typed message through encryption", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const built = await engine.messageBuilder(Notes, NOTE).withId("frame").withEncryptor(cipher).build();

		const decrypted = built.open(Notes, { opener: cipher });
		await expect(decrypted).resolves.toEqual(NOTE);
	});

	it("rejects decoding under a codec the body does not satisfy", async () => {
		const built = await engine.frameBuilder(BODY).withId("frame").build();
		await expect(built.open(Notes)).rejects.toThrow();
	});

	it("rejects typed decode of an encrypted frame", async () => {
		const cipher = engine.aes256Gcm({ key: AES_KEY, keyId: KEY_ID });
		const built = await engine.messageBuilder(Notes, NOTE).withId("frame").withEncryptor(cipher).build();

		await expect(built.open(Notes)).rejects.toMatchObject({
			code: "OpaqueBody",
			layer: "opener",
		});
	});

	it("installs a full-DER body, matching the Rust Doc schema", async () => {
		const built = await engine.messageBuilder(Doc, { title: "typed-body" }).withId("frame").build();

		// The exact DER the Rust interop test produces for the same Doc.
		const expected = new Uint8Array([0x30, 0x0c, 0x0c, 0x0a, ...new TextEncoder().encode("typed-body")]);
		expect(built.bodyDer).toEqual(expected);
		expect(await built.open(Doc)).toEqual({ title: "typed-body" });
	});

	it("commits to the typed body DER, not the payload", async () => {
		const built = await engine
			.messageBuilder(Doc, { title: "committed" })
			.withId("frame")
			.withMessageHasher(engine.sha3_256)
			.build();

		await expect(built.messageCommitmentVerdict(EMPTY_SALT)).resolves.toBe("verified");
	});
});
