import { runInNewContext } from "node:vm";

import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";

import type { TransportErrorCode } from "./index.js";
import { Engine } from "./index.js";

const engine = await Engine.load();

const KEY_ID = new TextEncoder().encode("tbws/test/kek/v1");

/**
 * The shared key every AES-256-GCM seal in this suite uses.
 */
const SHARED_KEY = { key: new Uint8Array(32).fill(3), keyId: KEY_ID };

/**
 * A shared key 16 octets short of the AES-256 key size.
 */
const SHORT_KEY = { key: new Uint8Array(16), keyId: KEY_ID };

/**
 * A shared key whose identifier names nothing.
 */
const UNNAMED_KEY = { key: new Uint8Array(32), keyId: new Uint8Array() };

const REFUSED_BYTES = expect.objectContaining({ code: "InvalidBytes" });

/**
 * The body DER every seal in this suite carries.
 */
const BODY_DER = new Uint8Array([0x30, 0x03, 0x04, 0x01, 0x7f]);

/*
 * Models an untyped JavaScript caller of a shared-key constructor.
 */
interface LooseSharedKeyReader {
	aes256Gcm(shared: unknown): unknown;
}

const looseAes: LooseSharedKeyReader = engine;

/**
 * The content type `id-data`, as a dotted object identifier.
 */
const DATA = "1.2.840.113549.1.7.1";

describe("key wrappers", () => {
	interface RefusedKey {
		name: string;
		make: () => unknown;
		refusal: {
			readonly code: TransportErrorCode;
			readonly path?: string;
		};
	}

	const rejected: RefusedKey[] = [
		{
			name: "Secp256k1SigningKey with a short scalar",
			make: () => engine.signingKey(new Uint8Array(31)),
			refusal: { code: "InvalidSigningKey" },
		},
		{
			name: "Secp256k1VerifyingKey with a bad SEC1 length",
			make: () => engine.verifyingKey(new Uint8Array(32)),
			refusal: { code: "InvalidVerifyingKey" },
		},
		{
			name: "Aes256Gcm with a 16-byte key",
			make: () => engine.aes256Gcm(SHORT_KEY),
			refusal: { code: "KeyError", path: "shared.key" },
		},
		{
			name: "Aes256Gcm with an empty key identifier",
			make: () => engine.aes256Gcm(UNNAMED_KEY),
			refusal: { code: "EmptyKeyId", path: "shared.keyId" },
		},
		{
			name: "HpkeEncryptor with a bad SEC1 length",
			make: () => engine.hpkeEncryptor(new Uint8Array(31)),
			refusal: { code: "InvalidVerifyingKey" },
		},
		{
			name: "HpkeDecryptor with a short secret",
			make: () => engine.hpkeDecryptor(new Uint8Array(16)),
			refusal: { code: "InvalidSigningKey" },
		},
	];

	it.each(rejected)(
		"a key refusal carries the engine code: $name refuses with $refusal.code",
		({ make, refusal }) => {
			expect(make).toThrow(expect.objectContaining(refusal));
		},
	);

	it("passes the engine refusal of a missing key identifier through", () => {
		const unnamed = { key: SHARED_KEY.key };
		expect(() => looseAes.aes256Gcm(unnamed)).toThrow(REFUSED_BYTES);
	});
});

/*
 * Models an untyped JavaScript caller of the wasm byte boundary: method-syntax
 * members compare bivariant, so the loose signature compiles without
 * assertions.
 */
interface LooseBodyWrapper {
	wrap(message: unknown): Uint8Array;
}

const loosely: LooseBodyWrapper = { wrap: engine.opaque.encode };

/**
 * The bytes 1 and 2 as a `Uint8Array` of this realm.
 */
const LOCAL_BYTES = new Uint8Array([1, 2]);

/**
 * The bytes 1 and 2 as a `Uint8Array` of another realm, whose
 * `instanceof Uint8Array` answers false here.
 */
const FOREIGN_BYTES: unknown = runInNewContext("new Uint8Array([1, 2])");

/**
 * A view of wider elements from another realm.
 */
const FOREIGN_WIDE: unknown = runInNewContext("new Uint16Array([1, 2])");

/**
 * The opaque body DER that wraps the bytes 1 and 2: a SEQUENCE that holds
 * one OCTET STRING.
 */
const OPAQUE_ONE_TWO = new Uint8Array([0x30, 0x04, 0x04, 0x02, 0x01, 0x02]);

/**
 * The bytes 1 and 2, whose own `length` property claims 64 octets.
 */
const LYING_BYTES = new Uint8Array([1, 2]);
Object.defineProperty(LYING_BYTES, "length", { value: 64 });

describe("the wasm byte boundary", () => {
	it("refuses a number where bytes belong", () => {
		expect(() => loosely.wrap(7)).toThrow(REFUSED_BYTES);
	});

	it("reads a Uint8Array of another realm as its octets", () => {
		expect(loosely.wrap(FOREIGN_BYTES)).toEqual(OPAQUE_ONE_TWO);
	});

	it("reads a Uint8Array of this realm as its octets", () => {
		expect(engine.opaque.encode(LOCAL_BYTES)).toEqual(OPAQUE_ONE_TWO);
	});

	it("reads as many octets as the array holds, whatever its length property claims", () => {
		expect(engine.opaque.encode(LYING_BYTES)).toEqual(OPAQUE_ONE_TWO);
	});

	it("refuses a view of wider elements from another realm", () => {
		expect(() => loosely.wrap(FOREIGN_WIDE)).toThrow(REFUSED_BYTES);
	});

	it("refuses a view of wider elements", () => {
		const wide = new Uint16Array([1, 2]);
		expect(() => loosely.wrap(wide)).toThrow(REFUSED_BYTES);
	});
});

describe("profile algorithm identifiers", () => {
	it("the profile hasher declares the profile digest OID", () => {
		const algorithm = engine.sha3_256.algorithmOid;
		expect(algorithm.equals(engine.profile.sha3_256)).toBe(true);
	});
});

describe("Engine.oid", () => {
	it("keeps the dotted form of an identifier the engine encodes", () => {
		const oid = engine.oid(DATA);
		expect(oid.toString()).toBe(DATA);
	});

	it.each([
		{ name: "a word", dotted: "not-an-oid" },
		{ name: "a first arc above 2", dotted: "3.1" },
		{ name: "a trailing dot", dotted: "1.2." },
	])("refuses $name with InvalidOid", ({ dotted }) => {
		expect(() => engine.oid(dotted)).toThrow(expect.objectContaining({ code: "InvalidOid" }));
	});
});

describe("release", () => {
	const PREHASH = new Uint8Array(32).fill(4);

	/**
	 * A compressed SEC1 point on secp256k1, as a recipient public key.
	 */
	const RECIPIENT = new Uint8Array(33).fill(2);

	/**
	 * The refusal of a call on a released key.
	 */
	const KEY_RELEASED = expect.objectContaining({ code: "KeyReleased" });

	it("releases a signing key, so a later call refuses with KeyReleased", () => {
		const key = engine.signingKey(new Uint8Array(32).fill(1));
		key[Symbol.dispose]();
		expect(() => key.signerId()).toThrow(KEY_RELEASED);
	});

	it("releases a shared key, so a later seal rejects with KeyReleased", async () => {
		const cipher = engine.aes256Gcm(SHARED_KEY);
		cipher[Symbol.dispose]();
		await expect(cipher.encrypt(PREHASH, engine.profile.data)).rejects.toThrow(KEY_RELEASED);
	});

	it("releases a signing key, so a later signature rejects with KeyReleased", async () => {
		const key = engine.signingKey(new Uint8Array(32).fill(1));
		key[Symbol.dispose]();
		await expect(key.signPrehash(PREHASH)).rejects.toThrow(KEY_RELEASED);
	});

	it("releases a recipient secret, so a later open rejects", async () => {
		const secret = new Uint8Array(32).fill(1);
		const recipientKey = engine.signingKey(secret);
		const recipient = recipientKey.verifyingKey().toSec1Bytes();
		const encryptor = engine.hpkeEncryptor(recipient);
		const sealed = await encryptor.encrypt(BODY_DER, engine.profile.data);
		const twin = engine.hpkeDecryptor(secret);
		const decryptor = engine.hpkeDecryptor(secret);

		decryptor[Symbol.dispose]();

		await expect(twin.decrypt(sealed)).resolves.toEqual(BODY_DER);
		await expect(decryptor.decrypt(sealed)).rejects.toThrow(KEY_RELEASED);
	});

	it("a signing key releases its one verifying key, so the lent view refuses with KeyReleased", () => {
		const key = engine.signingKey(new Uint8Array(32).fill(1));
		const first = key.verifyingKey();
		const second = key.verifyingKey();

		key[Symbol.dispose]();

		expect(second).toBe(first);
		expect(() => first.toSec1Bytes()).toThrow(KEY_RELEASED);
	});

	it("releases a signing key after it lent its verifying key, so a later verifyingKey call refuses with KeyReleased", () => {
		const key = engine.signingKey(new Uint8Array(32).fill(1));
		key.verifyingKey();

		key[Symbol.dispose]();

		expect(() => key.verifyingKey()).toThrow(KEY_RELEASED);
	});

	it("releases an HPKE encryptor, so a later seal rejects with KeyReleased", async () => {
		const encryptor = engine.hpkeEncryptor(RECIPIENT);
		encryptor[Symbol.dispose]();

		await expect(encryptor.encrypt(BODY_DER, engine.profile.data)).rejects.toThrow(KEY_RELEASED);
	});
});

describe("Secp256k1SigningKey.toSpkiDer", () => {
	// The EncodePublicKey SPKI of the scalar of 32 octets 0x01, an uncompressed SEC1 point.
	const SPKI_HEX =
		"3056301006072a8648ce3d020106052b8104000a034200041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1";

	it("emits uncompressed SPKI matching EncodePublicKey", () => {
		const key = engine.signingKey(new Uint8Array(32).fill(1));
		const spki = key.toSpkiDer();
		expect(spki.length).toBe(88);
		expect(spki[0]).toBe(0x30);
		expect(spki[1]).toBe(0x56);
		expect(spki[23]).toBe(0x04);
		expect(bytesToHex(spki)).toBe(SPKI_HEX);
	});
});

describe("profile Hasher", () => {
	it("computes the SHA3-256 test vector for 'abc'", async () => {
		const abc = new TextEncoder().encode("abc");
		const digest = await engine.sha3_256.digest(abc);

		const digestHex = bytesToHex(digest);
		expect(digestHex).toBe("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
	});
});

describe("profile encryptors", () => {
	const SECRET = new Uint8Array(32).fill(1);

	it("Aes256Gcm seals and opens a body DER", async () => {
		const cipher = engine.aes256Gcm(SHARED_KEY);
		const sealed = await cipher.encrypt(BODY_DER, engine.profile.data);
		expect(sealed.envelopeDer.length).toBeGreaterThan(0);
		expect(sealed.ciphertext).not.toEqual(BODY_DER);

		await expect(cipher.decrypt(sealed)).resolves.toEqual(BODY_DER);
	});

	it("HpkeEncryptor seals to a recipient the HpkeDecryptor opens", async () => {
		const recipientKey = engine.signingKey(SECRET);
		const recipient = recipientKey.verifyingKey().toSec1Bytes();
		const encryptor = engine.hpkeEncryptor(recipient);
		const sealed = await encryptor.encrypt(BODY_DER, engine.profile.data);

		const decryptor = engine.hpkeDecryptor(SECRET);
		await expect(decryptor.decrypt(sealed)).resolves.toEqual(BODY_DER);
	});

	it("Aes256Gcm refuses a body sealed to an HPKE recipient", async () => {
		const recipientKey = engine.signingKey(SECRET);
		const recipient = recipientKey.verifyingKey().toSec1Bytes();
		const encryptor = engine.hpkeEncryptor(recipient);
		const sealed = await encryptor.encrypt(BODY_DER, engine.profile.data);

		const cipher = engine.aes256Gcm(SHARED_KEY);
		await expect(cipher.decrypt(sealed)).rejects.toMatchObject({
			code: "EnvelopeError",
		});
	});

	it("HpkeDecryptor refuses a body sealed under a shared key", async () => {
		const cipher = engine.aes256Gcm(SHARED_KEY);
		const sealed = await cipher.encrypt(BODY_DER, engine.profile.data);

		const decryptor = engine.hpkeDecryptor(SECRET);
		await expect(decryptor.decrypt(sealed)).rejects.toMatchObject({
			code: "EnvelopeError",
		});
	});

	it.each([
		{ name: "Aes256Gcm", opener: engine.aes256Gcm(SHARED_KEY) },
		{ name: "HpkeDecryptor", opener: engine.hpkeDecryptor(SECRET) },
	])("$name refuses an envelope that is no AuthEnvelopedData", async ({ opener }) => {
		const sealed = {
			envelopeDer: new Uint8Array([0x30, 0x00]),
			ciphertext: new Uint8Array([1, 2, 3]),
		};

		await expect(opener.decrypt(sealed)).rejects.toMatchObject({
			code: "SerializationError",
		});
	});
});
