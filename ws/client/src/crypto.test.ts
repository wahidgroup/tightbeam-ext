import { describe, expect, it } from "vitest";

import { profileOids } from "#wasm";

import { ValidationError } from "./builder/errors.js";
import { MessagePriority, priorityFromOrdinal } from "./builder/priority.js";
import { Version, versionFromOrdinal } from "./builder/version.js";
import { initClient } from "./index.js";
import {
	Aes256Gcm,
	EciesDecryptor,
	EciesEncryptor,
	PROFILE_OIDS,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	Sha3_256,
} from "./crypto.js";

await initClient();

/**
 * Lowercase hex encoding of `bytes` (no Node `Buffer`).
 */
function bytesToHex(bytes: Uint8Array): string {
	let hex = "";
	for (const byte of bytes) {
		hex += byte.toString(16).padStart(2, "0");
	}

	return hex;
}

describe("enum ordinals", () => {
	it.each([
		{ name: "V0", value: Version.V0, ordinal: 0 },
		{ name: "V1", value: Version.V1, ordinal: 1 },
		{ name: "V2", value: Version.V2, ordinal: 2 },
		{ name: "V3", value: Version.V3, ordinal: 3 },
	])(
		"Version.$name is wire ordinal $ordinal and round-trips",
		({ value, ordinal }) => {
			expect(value).toBe(ordinal);
			expect(versionFromOrdinal(ordinal)).toBe(value);
		},
	);

	it("versionFromOrdinal rejects an out-of-range ordinal", () => {
		expect(versionFromOrdinal(4)).toBeUndefined();
	});

	it.each([
		{ name: "LowEffort", value: MessagePriority.LowEffort, ordinal: 0 },
		{ name: "Standard", value: MessagePriority.Standard, ordinal: 1 },
		{
			name: "HighThroughput",
			value: MessagePriority.HighThroughput,
			ordinal: 2,
		},
		{ name: "LowLatency", value: MessagePriority.LowLatency, ordinal: 3 },
		{ name: "Expedited", value: MessagePriority.Expedited, ordinal: 4 },
		{
			name: "NetworkControl",
			value: MessagePriority.NetworkControl,
			ordinal: 5,
		},
	])(
		"MessagePriority.$name is wire ordinal $ordinal and round-trips",
		({ value, ordinal }) => {
			expect(value).toBe(ordinal);
			expect(priorityFromOrdinal(ordinal)).toBe(value);
		},
	);

	it("priorityFromOrdinal rejects an out-of-range ordinal", () => {
		expect(priorityFromOrdinal(6)).toBeUndefined();
	});
});

describe("key wrappers", () => {
	interface LengthCase {
		name: string;
		make: () => unknown;
	}

	const rejected: LengthCase[] = [
		{
			name: "Secp256k1SigningKey with a short scalar",
			make: () => Secp256k1SigningKey.fromBytes(new Uint8Array(31)),
		},
		{
			name: "Secp256k1VerifyingKey with a bad SEC1 length",
			make: () => Secp256k1VerifyingKey.fromSec1Bytes(new Uint8Array(32)),
		},
		{
			name: "Aes256Gcm with a 16-byte key",
			make: () => Aes256Gcm.fromKey(new Uint8Array(16)),
		},
		{
			name: "EciesEncryptor with a bad SEC1 length",
			make: () => EciesEncryptor.fromBytes(new Uint8Array(31)),
		},
		{
			name: "EciesDecryptor with a short secret",
			make: () => EciesDecryptor.fromBytes(new Uint8Array(16)),
		},
	];

	it.each(rejected)("rejects $name", ({ make }) => {
		expect(make).toThrow(ValidationError);
	});
});

describe("profile algorithm identifiers", () => {
	it("PROFILE_OIDS matches the OIDs the wasm engine reports", () => {
		expect(profileOids()).toEqual(PROFILE_OIDS);
	});

	it("Sha3_256 declares the profile digest OID", () => {
		expect(new Sha3_256().algorithmOid).toBe(PROFILE_OIDS.sha3_256);
	});

	it("Secp256k1SigningKey declares the profile signature OIDs", () => {
		const key = Secp256k1SigningKey.fromBytes(new Uint8Array(32).fill(1));
		expect(key.signatureAlgorithmOid).toBe(PROFILE_OIDS.ecdsaWithSha3_256);
		expect(key.digestAlgorithmOid).toBe(PROFILE_OIDS.sha3_256);
	});
});

describe("profile Hasher", () => {
	it("computes the SHA3-256 test vector for 'abc'", async () => {
		const digest = await new Sha3_256().digest(
			new TextEncoder().encode("abc"),
		);

		const digestHex = bytesToHex(digest);
		expect(digestHex).toBe(
			"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
		);
	});
});

describe("profile encryptors", () => {
	const BODY_DER = new Uint8Array([0x30, 0x03, 0x04, 0x01, 0x7f]);

	it("Aes256Gcm seals and opens a body DER", async () => {
		const cipher = Aes256Gcm.fromKey(new Uint8Array(32).fill(3));
		const sealed = await cipher.encrypt(BODY_DER);
		expect(sealed.algorithmOid).toBe(PROFILE_OIDS.aes256Gcm);
		expect(sealed.parametersDer).toBeDefined();
		expect(sealed.ciphertext).not.toEqual(BODY_DER);

		await expect(cipher.decrypt(sealed)).resolves.toEqual(BODY_DER);
	});

	it("EciesEncryptor seals to a recipient the EciesDecryptor opens", async () => {
		const secret = new Uint8Array(32).fill(1);
		const recipient = Secp256k1SigningKey.fromBytes(secret)
			.verifyingKey()
			.toSec1Bytes();

		const sealed =
			await EciesEncryptor.fromBytes(recipient).encrypt(BODY_DER);
		expect(sealed.algorithmOid).toBe(PROFILE_OIDS.eciesSecp256k1);

		await expect(
			EciesDecryptor.fromBytes(secret).decrypt(sealed),
		).resolves.toEqual(BODY_DER);
	});

	it.each([
		{
			name: "Aes256Gcm",
			decrypt: (sealed: Parameters<Aes256Gcm["decrypt"]>[0]) =>
				Aes256Gcm.fromKey(new Uint8Array(32).fill(3)).decrypt(sealed),
		},
		{
			name: "EciesDecryptor",
			decrypt: (sealed: Parameters<EciesDecryptor["decrypt"]>[0]) =>
				EciesDecryptor.fromBytes(new Uint8Array(32).fill(1)).decrypt(
					sealed,
				),
		},
	])(
		"$name rejects a body sealed under a different algorithm",
		async ({ decrypt }) => {
			const sealed = {
				algorithmOid: "1.2.3.4",
				ciphertext: new Uint8Array([1, 2, 3]),
			};

			await expect(decrypt(sealed)).rejects.toThrow(ValidationError);
		},
	);
});
