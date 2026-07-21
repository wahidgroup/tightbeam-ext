import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha3_256, sha3_512 } from "@noble/hashes/sha3.js";
import { describe, expect, it } from "vitest";

import { bodyPreimage, profileSignerId } from "#wasm";

import type {
	BodyCompressor,
	BodyInflator,
	CompressedBody,
} from "./compress.js";
import type {
	BodyDecryptor,
	BodyEncryptor,
	EncryptedBody,
	Hasher,
	Signatory,
} from "./crypto.js";
import type { FrameBuilder, MessageCodec } from "./index.js";
import { MessagePriority } from "./builder/priority.js";
import { Version } from "./builder/version.js";
import {
	Aes256Gcm,
	EciesDecryptor,
	EciesEncryptor,
	PROFILE_OIDS,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	Sha3_256,
} from "./crypto.js";
import {
	Opaque,
	ValidationError,
	frame,
	initClient,
	wrapped,
} from "./index.js";

/**
 * Wasm-backed round-trips through the real codec: what the builder writes,
 * `Frame` must read back - with the profile algorithms and with
 * caller-supplied (noble-backed) ones.
 */

const BODY = new Uint8Array([1, 2, 3, 4]);
const SIGNING_KEY = Secp256k1SigningKey.fromBytes(new Uint8Array(32).fill(1));
const AES_KEY = new Uint8Array(32).fill(7);
const EMPTY_SALT = new Uint8Array();

/**
 * The SHA3-512 OID, an algorithm outside the tightbeam profile.
 */
const SHA3_512_OID = "2.16.840.1.101.3.4.2.10";

/**
 * A {@link Hasher} backed by an independent JavaScript digest (noble),
 * standing in for any bring-your-own hash library.
 */
class NobleHasher implements Hasher {
	constructor(
		readonly algorithmOid: string,
		private readonly hash: (data: Uint8Array) => Uint8Array,
	) {}

	digest(data: Uint8Array): Promise<Uint8Array> {
		const digest = this.hash(data);
		const result = Promise.resolve(digest);
		return result;
	}
}

await initClient();

describe("Frame metadata round-trip", () => {
	it("reads back a cleartext V0 frame", async () => {
		const expectedId = new TextEncoder().encode("clear-1");

		const built = await frame(BODY).withId("clear-1").withOrder(7).build();
		expect(built.version).toBe(Version.V0);
		expect(built.id).toEqual(expectedId);
		expect(built.order).toBe(7n);
		expect(built.message(Opaque)).toEqual(BODY);
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

		const built = await frame(BODY)
			.withId("rich")
			.withOrder(21)
			.withPriority(MessagePriority.Expedited)
			.withLifetime(300)
			.withPreviousHash({
				algorithmOid: SHA3_512_OID,
				digest,
			})
			.withMatrix(2, matrix)
			.build();
		expect(built.version).toBe(Version.V3);
		expect(built.priority).toBe(MessagePriority.Expedited);
		expect(built.lifetime).toBe(300n);
		expect(built.previousFrame?.algorithmOid).toBe(SHA3_512_OID);
		expect(built.previousFrame?.digest).toEqual(digest);
		expect(built.matrix?.n).toBe(2);
		expect(built.matrix?.data).toEqual(matrix);
	});

	it("honors a matching version assertion against the real codec", async () => {
		const built = await frame(BODY)
			.withSigner(SIGNING_KEY)
			.assertVersion(Version.V1)
			.build();
		expect(built.version).toBe(Version.V1);
	});
});

describe("version-floor parity with tightbeam-rs", () => {
	interface FloorCase {
		field: string;
		expected: Version;
		make: () => FrameBuilder;
	}

	const aeadEncryptor = Aes256Gcm.fromKey(AES_KEY);
	const recipientPublic = SIGNING_KEY.verifyingKey().toSec1Bytes();
	const eciesEncryptor = EciesEncryptor.fromBytes(recipientPublic);

	const cases: FloorCase[] = [
		{
			field: "bare payload",
			expected: Version.V0,
			make: () => frame(BODY),
		},
		{
			field: "signer",
			expected: Version.V1,
			make: () => frame(BODY).withSigner(SIGNING_KEY),
		},
		{
			field: "aead encryptor",
			expected: Version.V1,
			make: () => frame(BODY).withEncryptor(aeadEncryptor),
		},
		{
			field: "ecies encryptor",
			expected: Version.V1,
			make: () => frame(BODY).withEncryptor(eciesEncryptor),
		},
		{
			field: "priority",
			expected: Version.V2,
			make: () => frame(BODY).withPriority(MessagePriority.Standard),
		},
		{
			field: "lifetime",
			expected: Version.V2,
			make: () => frame(BODY).withLifetime(60),
		},
		{
			field: "previous hash",
			expected: Version.V2,
			make: () =>
				frame(BODY).withPreviousHash({
					algorithmOid: PROFILE_OIDS.sha3_256,
					digest: new Uint8Array(32).fill(1),
				}),
		},
		{
			field: "message hasher",
			expected: Version.V2,
			make: () => frame(BODY).withMessageHasher(new Sha3_256()),
		},
		{
			field: "witness hasher",
			expected: Version.V2,
			make: () => frame(BODY).withWitnessHasher(new Sha3_256()),
		},
		{
			field: "matrix",
			expected: Version.V3,
			make: () => frame(BODY).withMatrix(2, new Uint8Array([0, 1, 1, 0])),
		},
	];

	it.each(cases)(
		"derives V$expected for $field on both sides of the boundary",
		async ({ expected, make }) => {
			const built = await make().assertVersion(expected).build();
			expect(built.version).toBe(expected);
		},
	);
});

describe("Frame.verify", () => {
	it("verifies a locally signed frame with the derived key", async () => {
		const built = await frame(BODY)
			.withId("signed")
			.withOrder(1)
			.withSigner(SIGNING_KEY)
			.build();

		expect(built.signed).toBe(true);
		expect(built.signatureInfo?.algorithmOid).toBe(
			PROFILE_OIDS.ecdsaWithSha3_256,
		);
		expect(built.signatureInfo?.digestAlgorithmOid).toBe(
			PROFILE_OIDS.sha3_256,
		);
		expect(() => built.verify(SIGNING_KEY.verifyingKey())).not.toThrow();
	});

	it("rejects verification under the wrong key", async () => {
		const other = Secp256k1SigningKey.fromBytes(new Uint8Array(32).fill(2));
		const otherKey = other.verifyingKey();

		const signed = await frame(BODY).withSigner(SIGNING_KEY).build();
		expect(() => signed.verify(otherKey)).toThrow();
	});

	it("rejects verification of an unsigned frame", async () => {
		const unsigned = await frame(BODY).build();
		expect(() => unsigned.verify(SIGNING_KEY.verifyingKey())).toThrow();
	});

	it("verifies a profile signature externally from tbs and signatureInfo", async () => {
		const built = await frame(BODY).withSigner(SIGNING_KEY).build();

		const info = built.signatureInfo;
		expect(info?.algorithmOid).toBe(PROFILE_OIDS.ecdsaWithSha3_256);

		const signature = info?.signature ?? new Uint8Array();
		const tbsDigest = sha3_256(built.tbs());
		const publicKey = SIGNING_KEY.verifyingKey().toSec1Bytes();
		const valid = secp256k1.verify(signature, tbsDigest, publicKey, {
			prehash: false,
		});
		expect(valid).toBe(true);
	});
});

describe("Frame.frameIntegrityVerdict", () => {
	it.each([
		{ name: "profile SHA3-256", hasher: new Sha3_256() },
		{
			name: "noble SHA3-512 (bring-your-own)",
			hasher: new NobleHasher(SHA3_512_OID, sha3_512),
		},
	])(
		"reports verified under the matching $name hasher",
		async ({ hasher }) => {
			const witnessed = await frame(BODY)
				.withWitnessHasher(hasher)
				.build();

			await expect(witnessed.frameIntegrityVerdict(hasher)).resolves.toBe(
				"verified",
			);
		},
	);

	it("reports absent for an unwitnessed frame", async () => {
		const bare = await frame(BODY).build();
		await expect(bare.frameIntegrityVerdict()).resolves.toBe("absent");
	});

	it("reports algorithm-mismatch when checked under the wrong hasher", async () => {
		const nobleSha3_512 = new NobleHasher(SHA3_512_OID, sha3_512);
		const profileHasher = new Sha3_256();

		const witnessed = await frame(BODY)
			.withWitnessHasher(nobleSha3_512)
			.build();

		await expect(
			witnessed.frameIntegrityVerdict(profileHasher),
		).resolves.toBe("algorithm-mismatch");
	});

	it("agrees across implementations of the same algorithm", async () => {
		const nobleSha3_256 = new NobleHasher(PROFILE_OIDS.sha3_256, sha3_256);
		const profileHasher = new Sha3_256();

		const witnessed = await frame(BODY)
			.withWitnessHasher(nobleSha3_256)
			.build();

		await expect(
			witnessed.frameIntegrityVerdict(profileHasher),
		).resolves.toBe("verified");
	});
});

describe("Frame.messageCommitmentVerdict", () => {
	const SALT = new TextEncoder().encode("pepper");

	it("reports verified for the disclosed salt", async () => {
		const committed = await frame(BODY)
			.withMessageHasher(new Sha3_256(), SALT)
			.build();

		await expect(committed.messageCommitmentVerdict(SALT)).resolves.toBe(
			"verified",
		);
	});

	it("reports mismatch for the wrong salt", async () => {
		const wrongSalt = new TextEncoder().encode("wrong");

		const committed = await frame(BODY)
			.withMessageHasher(new Sha3_256(), SALT)
			.build();

		await expect(
			committed.messageCommitmentVerdict(wrongSalt),
		).resolves.toBe("mismatch");
	});

	it("reports absent for a frame without a commitment", async () => {
		const bare = await frame(BODY).build();
		await expect(bare.messageCommitmentVerdict(SALT)).resolves.toBe(
			"absent",
		);
	});
});

describe("external Signatory across the wasm boundary", () => {
	/**
	 * A {@link Signatory} backed by an independent JavaScript secp256k1
	 * implementation (noble), standing in for a wallet or HSM: the wasm
	 * module never sees the secret key, yet must verify the signature it
	 * produces. Records each TBS that crosses the boundary.
	 */
	class NobleSignatory implements Signatory {
		readonly signatureAlgorithmOid = PROFILE_OIDS.ecdsaWithSha3_256;
		readonly digestAlgorithmOid = PROFILE_OIDS.sha3_256;
		readonly seen: Uint8Array[] = [];

		constructor(private readonly secret: Uint8Array) {}

		publicKey(): Uint8Array {
			const publicKey = secp256k1.getPublicKey(this.secret, true);
			return publicKey;
		}

		signerId(): Uint8Array {
			const id = profileSignerId(this.publicKey());
			return id;
		}

		sign(tbs: Uint8Array): Promise<Uint8Array> {
			this.seen.push(tbs);
			const digest = sha3_256(tbs);
			const signature = secp256k1.sign(digest, this.secret, {
				prehash: false,
			});

			const result = Promise.resolve(signature);
			return result;
		}
	}

	it("attaches a noble-produced signature that wasm verification accepts", async () => {
		const signatory = new NobleSignatory(new Uint8Array(32).fill(5));
		const built = await frame(BODY)
			.withId("external")
			.withOrder(11)
			.withSigner(signatory)
			.build();

		expect(built.signed).toBe(true);
		const verifyingKey = Secp256k1VerifyingKey.fromSec1Bytes(
			signatory.publicKey(),
		);
		expect(() => built.verify(verifyingKey)).not.toThrow();
	});

	it("rejects verification of the external signature under another key", async () => {
		const signatory = new NobleSignatory(new Uint8Array(32).fill(5));
		const built = await frame(BODY).withSigner(signatory).build();

		expect(() => built.verify(SIGNING_KEY.verifyingKey())).toThrow();
	});

	it("validates the spec before anything crosses to the signatory", async () => {
		const signatory = new NobleSignatory(new Uint8Array(32).fill(5));
		const attempt = frame().withSigner(signatory).build();

		await expect(attempt).rejects.toThrow(ValidationError);
		expect(signatory.seen).toEqual([]);
	});
});

describe("Frame.decryptMessage", () => {
	it("round-trips an AES-256-GCM sealed body", async () => {
		const cipher = Aes256Gcm.fromKey(AES_KEY);
		const cleartextBodyDer = bodyPreimage(BODY);

		const built = await frame(BODY).withEncryptor(cipher).build();
		expect(built.confidential).toBe(true);
		expect(built.confidentialityInfo?.algorithmOid).toBe(
			PROFILE_OIDS.aes256Gcm,
		);
		expect(built.bodyDer).not.toEqual(cleartextBodyDer);

		await expect(built.decryptMessage(cipher, Opaque)).resolves.toEqual(
			BODY,
		);
	});

	it("rejects the wrong AEAD key", async () => {
		const cipher = Aes256Gcm.fromKey(AES_KEY);
		const wrongKey = new Uint8Array(32).fill(9);
		const wrong = Aes256Gcm.fromKey(wrongKey);

		const built = await frame(BODY).withEncryptor(cipher).build();
		await expect(built.decryptMessage(wrong, Opaque)).rejects.toThrow();
	});

	it("round-trips an ECIES body sealed to a recipient", async () => {
		const recipientSecret = new Uint8Array(32).fill(1);
		const recipientPublic = SIGNING_KEY.verifyingKey().toSec1Bytes();
		const encryptor = EciesEncryptor.fromBytes(recipientPublic);
		const cleartextBodyDer = bodyPreimage(BODY);

		const built = await frame(BODY).withEncryptor(encryptor).build();
		expect(built.confidential).toBe(true);
		expect(built.confidentialityInfo?.algorithmOid).toBe(
			PROFILE_OIDS.eciesSecp256k1,
		);
		expect(built.bodyDer).not.toEqual(cleartextBodyDer);

		const decryptor = EciesDecryptor.fromBytes(recipientSecret);
		await expect(built.decryptMessage(decryptor, Opaque)).resolves.toEqual(
			BODY,
		);
	});

	it("rejects the wrong ECIES secret", async () => {
		const recipientPublic = SIGNING_KEY.verifyingKey().toSec1Bytes();
		const encryptor = EciesEncryptor.fromBytes(recipientPublic);
		const built = await frame(BODY).withEncryptor(encryptor).build();

		const wrongSecret = new Uint8Array(32).fill(2);
		const wrong = EciesDecryptor.fromBytes(wrongSecret);
		await expect(built.decryptMessage(wrong, Opaque)).rejects.toThrow();
	});

	it("rejects decryption of a cleartext frame", async () => {
		const cipher = Aes256Gcm.fromKey(AES_KEY);
		const cleartext = await frame(BODY).build();

		await expect(cleartext.decryptMessage(cipher, Opaque)).rejects.toThrow(
			ValidationError,
		);
	});
});

describe("bring-your-own encryption across the wasm boundary", () => {
	/**
	 * DER-encode an OCTET STRING (short form), the parameter layout the
	 * profile uses to carry the GCM nonce.
	 */
	function derOctetString(bytes: Uint8Array): Uint8Array {
		const der = new Uint8Array([0x04, bytes.length, ...bytes]);
		return der;
	}

	/**
	 * An AES-256-GCM {@link BodyEncryptor} / {@link BodyDecryptor} backed
	 * by WebCrypto instead of the wasm module: the sealed pieces it emits
	 * and consumes must interoperate with the profile implementation.
	 */
	class WebCryptoAes256Gcm implements BodyEncryptor, BodyDecryptor {
		constructor(private readonly key: Uint8Array<ArrayBuffer>) {}

		private cryptoKey(usage: KeyUsage): Promise<CryptoKey> {
			const key = crypto.subtle.importKey(
				"raw",
				this.key,
				"AES-GCM",
				false,
				[usage],
			);
			return key;
		}

		async encrypt(bodyDer: Uint8Array): Promise<EncryptedBody> {
			const nonce = crypto.getRandomValues(new Uint8Array(12));
			const algorithm = { name: "AES-GCM", iv: nonce };
			const cryptoKey = await this.cryptoKey("encrypt");
			const bodyDerView = new Uint8Array(bodyDer);
			const sealed = await crypto.subtle.encrypt(
				algorithm,
				cryptoKey,
				bodyDerView,
			);

			const encryptedBody = {
				algorithmOid: PROFILE_OIDS.aes256Gcm,
				parametersDer: derOctetString(nonce),
				ciphertext: new Uint8Array(sealed),
			};
			return encryptedBody;
		}

		async decrypt(sealed: EncryptedBody): Promise<Uint8Array> {
			// Strip the 2-octet OCTET STRING header to recover the nonce.
			const parameters = sealed.parametersDer ?? new Uint8Array();
			const nonce = new Uint8Array(parameters.slice(2));
			const algorithm = { name: "AES-GCM", iv: nonce };
			const cryptoKey = await this.cryptoKey("decrypt");
			const ciphertext = new Uint8Array(sealed.ciphertext);
			const opened = await crypto.subtle.decrypt(
				algorithm,
				cryptoKey,
				ciphertext,
			);

			const plaintext = new Uint8Array(opened);
			return plaintext;
		}
	}

	it("opens a WebCrypto-sealed body with the profile decryptor", async () => {
		const encryptor = new WebCryptoAes256Gcm(AES_KEY);
		const built = await frame(BODY).withEncryptor(encryptor).build();
		expect(built.confidentialityInfo?.algorithmOid).toBe(
			PROFILE_OIDS.aes256Gcm,
		);

		const decryptor = Aes256Gcm.fromKey(AES_KEY);
		await expect(built.decryptMessage(decryptor, Opaque)).resolves.toEqual(
			BODY,
		);
	});

	it("opens a profile-sealed body with the WebCrypto decryptor", async () => {
		const encryptor = Aes256Gcm.fromKey(AES_KEY);
		const built = await frame(BODY).withEncryptor(encryptor).build();

		const decryptor = new WebCryptoAes256Gcm(AES_KEY);
		await expect(built.decryptMessage(decryptor, Opaque)).resolves.toEqual(
			BODY,
		);
	});
});

describe("bring-your-own compression", () => {
	/**
	 * The `id-ct-compressedData` OID the engine records when the
	 * compressor declares no content type.
	 */
	const COMPRESSED_CONTENT_OID = "1.2.840.113549.1.9.16.1.9";

	/**
	 * Run `bytes` through a compression or decompression transform stream.
	 */
	async function pump(
		transform: ReadableWritablePair<Uint8Array, BufferSource>,
		bytes: Uint8Array,
	): Promise<Uint8Array> {
		const input = new Uint8Array(bytes);
		const source = new Blob([input]).stream().pipeThrough(transform);

		const collected = await new Response(source).arrayBuffer();
		const output = new Uint8Array(collected);
		return output;
	}

	/**
	 * A zlib {@link BodyCompressor} / {@link BodyInflator} backed by the
	 * platform-native `CompressionStream("deflate")`, standing in for any
	 * bring-your-own compression library.
	 */
	class ZlibCompression implements BodyCompressor, BodyInflator {
		async compress(bodyDer: Uint8Array): Promise<CompressedBody> {
			const data = await pump(new CompressionStream("deflate"), bodyDer);
			const compressed = { algorithmOid: PROFILE_OIDS.zlib, data };
			return compressed;
		}

		async decompress(compressed: CompressedBody): Promise<Uint8Array> {
			if (compressed.algorithmOid !== PROFILE_OIDS.zlib) {
				throw new ValidationError("COMPRESSION_ALGORITHM", [
					{
						path: "compactness.algorithmOid",
						message: `Expected zlib, got ${compressed.algorithmOid}`,
					},
				]);
			}

			const bodyDer = await pump(
				new DecompressionStream("deflate"),
				compressed.data,
			);
			return bodyDer;
		}
	}

	const zlib = new ZlibCompression();

	it("round-trips a compressed cleartext body", async () => {
		const uncompressedBodyDer = bodyPreimage(BODY);

		const built = await frame(BODY).withCompressor(zlib).build();
		expect(built.compressed).toBe(true);
		expect(built.compactnessInfo?.algorithmOid).toBe(PROFILE_OIDS.zlib);
		expect(built.compactnessInfo?.contentOid).toBe(COMPRESSED_CONTENT_OID);
		expect(built.bodyDer).not.toEqual(uncompressedBodyDer);

		await expect(built.inflateMessage(zlib, Opaque)).resolves.toEqual(BODY);
	});

	it("round-trips a compressed-then-sealed body", async () => {
		const cipher = Aes256Gcm.fromKey(AES_KEY);
		const built = await frame(BODY)
			.withCompressor(zlib)
			.withEncryptor(cipher)
			.build();

		expect(built.compressed).toBe(true);
		expect(built.confidential).toBe(true);
		await expect(
			built.decryptMessage(cipher, Opaque, zlib),
		).resolves.toEqual(BODY);
	});

	it("rejects decryption of a compressed body without an inflator", async () => {
		const cipher = Aes256Gcm.fromKey(AES_KEY);
		const built = await frame(BODY)
			.withCompressor(zlib)
			.withEncryptor(cipher)
			.build();

		await expect(built.decryptMessage(cipher, Opaque)).rejects.toThrow(
			ValidationError,
		);
	});

	it("rejects a plain read of a compressed body", async () => {
		const built = await frame(BODY).withCompressor(zlib).build();
		expect(() => built.message(Opaque)).toThrow(ValidationError);
	});

	it("rejects inflation of an uncompressed frame", async () => {
		const bare = await frame(BODY).build();
		await expect(bare.inflateMessage(zlib, Opaque)).rejects.toThrow(
			ValidationError,
		);
	});

	it("commits to the uncompressed body, so the carried digest only checks out after inflation", async () => {
		const built = await frame(BODY)
			.withMessageHasher(new Sha3_256())
			.withCompressor(zlib)
			.build();

		await expect(built.messageCommitmentVerdict(EMPTY_SALT)).resolves.toBe(
			"mismatch",
		);

		const bodyDer = await built.inflateMessage(zlib, Opaque);
		expect(bodyDer).toEqual(BODY);
	});
});

describe("typed message codecs", () => {
	interface ChatMessage {
		author: string;
		text: string;
	}

	/**
	 * A wrapped payload codec: JSON inside the profile opaque body, with
	 * caller-side runtime validation on decode.
	 */
	const Chat: MessageCodec<ChatMessage> = wrapped({
		encode(message: ChatMessage): Uint8Array {
			const payload = new TextEncoder().encode(JSON.stringify(message));
			return payload;
		},
		decode(payload: Uint8Array): ChatMessage {
			const text = new TextDecoder().decode(payload);
			const parsed: unknown = JSON.parse(text);
			if (
				typeof parsed !== "object" ||
				parsed === null ||
				!("author" in parsed) ||
				!("text" in parsed) ||
				typeof parsed.author !== "string" ||
				typeof parsed.text !== "string"
			) {
				throw new ValidationError("CHAT_MESSAGE", [
					{ path: "body", message: "Not a chat message" },
				]);
			}

			const message = { author: parsed.author, text: parsed.text };
			return message;
		},
	});

	/**
	 * A full-DER codec for `SEQUENCE { title UTF8String }`, the schema of
	 * the Rust `Doc` interop test: no opaque wrapper, so a typed Rust peer
	 * decodes the body directly.
	 */
	const Doc: MessageCodec<{ title: string }> = {
		encode(message: { title: string }): Uint8Array {
			const title = new TextEncoder().encode(message.title);
			const bodyDer = new Uint8Array([
				0x30,
				title.length + 2,
				0x0c,
				title.length,
				...title,
			]);
			return bodyDer;
		},
		decode(bodyDer: Uint8Array): { title: string } {
			const length = bodyDer[3] ?? 0;
			if (
				bodyDer[0] !== 0x30 ||
				bodyDer[2] !== 0x0c ||
				bodyDer.length !== length + 4
			) {
				throw new ValidationError("DOC", [
					{ path: "body", message: "Not a Doc body" },
				]);
			}

			const title = new TextDecoder().decode(bodyDer.slice(4));
			return { title };
		},
	};

	const CHAT: ChatMessage = { author: "ada", text: "hello" };

	it("round-trips a wrapped typed message", async () => {
		const built = await frame().withMessage(Chat, CHAT).build();
		expect(built.message(Chat)).toEqual(CHAT);
	});

	it("round-trips a wrapped typed message through encryption", async () => {
		const cipher = Aes256Gcm.fromKey(AES_KEY);
		const built = await frame()
			.withMessage(Chat, CHAT)
			.withEncryptor(cipher)
			.build();

		await expect(built.decryptMessage(cipher, Chat)).resolves.toEqual(CHAT);
	});

	it("rejects decoding under a codec the body does not satisfy", async () => {
		const built = await frame(BODY).build();
		expect(() => built.message(Chat)).toThrow();
	});

	it("rejects typed decode of an encrypted frame", async () => {
		const cipher = Aes256Gcm.fromKey(AES_KEY);
		const built = await frame()
			.withMessage(Chat, CHAT)
			.withEncryptor(cipher)
			.build();

		expect(() => built.message(Chat)).toThrow(ValidationError);
	});

	it("installs a full-DER body, matching the Rust Doc schema", async () => {
		const built = await frame()
			.withMessage(Doc, { title: "typed-body" })
			.build();

		// The exact DER the Rust interop test produces for the same Doc.
		const expected = new Uint8Array([
			0x30,
			0x0c,
			0x0c,
			0x0a,
			...new TextEncoder().encode("typed-body"),
		]);
		expect(built.bodyDer).toEqual(expected);
		expect(built.message(Doc)).toEqual({ title: "typed-body" });
	});

	it("commits to the typed body DER, not the payload", async () => {
		const built = await frame()
			.withMessage(Doc, { title: "committed" })
			.withMessageHasher(new Sha3_256())
			.build();

		await expect(built.messageCommitmentVerdict(EMPTY_SALT)).resolves.toBe(
			"verified",
		);
	});
});
