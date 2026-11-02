/**
 * Cryptographic interfaces and the tightbeam profile implementations.
 */

import {
	Aes256Gcm as WasmAes256Gcm,
	HpkeSecp256k1Decryptor as WasmHpkeDecryptor,
	HpkeSecp256k1Encryptor as WasmHpkeEncryptor,
	Secp256k1SigningKey as WasmSecp256k1SigningKey,
	Secp256k1VerifyingKey as WasmSecp256k1VerifyingKey,
	Sha3_256 as WasmSha3_256,
} from "#wasm";

import { ValidationError } from "./builder/errors.js";

/**
 * The dotted OIDs of the tightbeam profile (`tightbeam::oids`).
 *
 * Literal values rather than reads from the wasm `profileOids()` binding,
 * so the table is usable before the (web-build) wasm module initializes.
 *
 * # Sources
 *
 * - RFC 8878, Zstandard compression:
 *   {@link https://datatracker.ietf.org/doc/html/rfc8878 RFC 8878}
 * - RFC 3274, Compressed Data Content Type:
 *   {@link https://datatracker.ietf.org/doc/html/rfc3274 RFC 3274}
 * - RFC 9629, Using Key Encapsulation Mechanism (KEM) Algorithms in CMS:
 *   {@link https://datatracker.ietf.org/doc/html/rfc9629 RFC 9629}
 */
export const PROFILE_OIDS = {
	/**
	 * SHA3-256, the profile digest.
	 */
	sha3_256: "2.16.840.1.101.3.4.2.8",
	/**
	 * secp256k1 ECDSA over SHA3-256, the profile signature.
	 */
	ecdsaWithSha3_256: "2.16.840.1.101.3.4.3.10",
	/**
	 * AES-256-GCM, the profile symmetric cipher.
	 */
	aes256Gcm: "2.16.840.1.101.3.4.1.46",
	/**
	 * DHKEM over secp256k1, the profile recipient KEM.
	 */
	dhkemSecp256k1: "1.3.6.1.4.1.64586.2.3",
	/**
	 * Zstandard, the profile compression.
	 */
	zstd: "1.3.6.1.4.1.64586.2.1",
	/**
	 * zlib, interoperable with `CompressionStream("deflate")`.
	 */
	zlib: "1.2.840.113549.1.9.16.3.8",
	/**
	 * id-data (RFC 5652): the content type recorded in the compactness info
	 * and in an envelope when the caller names none.
	 */
	data: "1.2.840.113549.1.7.1",
} as const;

/**
 * A digest capability. Implement it with any hash library.
 */
export interface Hasher {
	/**
	 * The dotted OID of the digest algorithm this hasher implements.
	 */
	readonly algorithmOid: string;

	/**
	 * Digest `data`, resolving with the raw digest octets.
	 */
	digest(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * A sealed frame body: the CMS envelope recorded in the frame's
 * confidentiality info, and the ciphertext that replaces the body. The
 * ciphertext travels detached from the envelope (RFC 5652 § 6.1).
 *
 * # Sources
 *
 * - RFC 5083, CMS Authenticated-Enveloped-Data Content Type:
 *   {@link https://datatracker.ietf.org/doc/html/rfc5083 RFC 5083}
 */
export interface EncryptedBody {
	/**
	 * The dotted OID of the content-encryption algorithm.
	 */
	readonly algorithmOid: string;

	/**
	 * The DER `AuthEnvelopedData`: the recipient, the content type, the
	 * nonce, and the tag, with its content detached.
	 */
	readonly envelopeDer: Uint8Array;

	/**
	 * The ciphertext.
	 */
	readonly ciphertext: Uint8Array;
}

/**
 * A body-encryption capability. It receives the body DER (the `bodyPreimage`)
 * and returns the sealed pieces.
 */
export interface BodyEncryptor {
	/**
	 * Seal `bodyDer`, resolving with its envelope and ciphertext.
	 *
	 * @param contentOid - Dotted content-type OID the envelope authenticates,
	 * or `id-data` when omitted.
	 */
	encrypt(bodyDer: Uint8Array, contentOid?: string): Promise<EncryptedBody>;
}

/**
 * The matching body-decryption capability for `Frame.decryptBytes`. It
 * receives the sealed pieces carried by the frame and resolves with the
 * plaintext body DER.
 */
export interface BodyDecryptor {
	/**
	 * Open `sealed`, resolving with the plaintext body DER.
	 */
	decrypt(sealed: EncryptedBody): Promise<Uint8Array>;
}

/**
 * Minimum frame surface a {@link FrameVerifier} needs. Kept structural so
 * crypto does not import {@link Frame} (avoids a crypto↔frame cycle).
 */
export interface VerifiableFrame {
	/**
	 * Frame DER octets.
	 */
	toDer(): Uint8Array;

	/**
	 * To-be-signed octets.
	 */
	tbs(): Uint8Array;

	/**
	 * The digest the frame's signature verifies over: the digest of its CMS
	 * signed attributes, which bind {@link tbs}.
	 */
	signaturePrehash(): Uint8Array;

	/**
	 * Carried signature metadata, when present.
	 */
	readonly signatureInfo?: {
		readonly algorithmOid: string;
		readonly signature: Uint8Array;
	};
}

/**
 * Unwrap/verify half of authenticity. Algorithm lives in the
 * implementation (profile secp256k1, BYO ed25519, …).
 */
export interface FrameVerifier {
	/**
	 * Verify this frame's non-repudiation signature.
	 *
	 * @throws when the frame is unsigned, the algorithm differs, or the
	 * signature does not verify.
	 */
	verifyFrame(frame: VerifiableFrame): void;
}

/**
 * A frame signer. Anything that can sign a digest under the profile signature
 * qualifies - a local {@link Secp256k1SigningKey}, wallets, passkeys, HSMs,
 * remote KMS backends. An external signer's private key never enters wasm
 * memory.
 *
 * A frame carries a CMS `SignerInfo`, whose form the wasm profile fixes, so a
 * signer signs ECDSA over secp256k1 with SHA3-256.
 */
export interface Signatory {
	/**
	 * The dotted OID of the signature algorithm this signer implements. The
	 * codec refuses any OID but `PROFILE_OIDS.ecdsaWithSha3_256`.
	 */
	readonly signatureAlgorithmOid: string;

	/**
	 * The dotted OID of the digest the signature algorithm names. The codec
	 * refuses any OID but `PROFILE_OIDS.sha3_256`.
	 */
	readonly digestAlgorithmOid: string;

	/**
	 * Present when this signer can derive its verify half (local keys).
	 * Envelope `signed(signatory)` uses it for `unwrap()` without a
	 * separate `verified()` declaration.
	 */
	readonly verifier?: FrameVerifier;

	/**
	 * The subject-key-identifier octets naming this signer's certificate in
	 * the frame (RFC 7093 § 2 method 1 for a profile key).
	 */
	signerId(): Uint8Array;

	/**
	 * Sign `prehash` directly, with no rehash, resolving with a DER
	 * `ECDSA-Sig-Value` (RFC 3279 § 2.2.3).
	 *
	 * The prehash is the digest of the frame's CMS signed attributes, which
	 * bind its to-be-signed bytes (RFC 5652 § 5.4).
	 */
	signPrehash(prehash: Uint8Array): Promise<Uint8Array>;
}

/**
 * Reject byte strings whose length is not one of `expected`.
 */
function requireLength(
	bytes: Uint8Array,
	expected: readonly number[],
	path: string,
): void {
	if (!expected.includes(bytes.length)) {
		throw new ValidationError("KEY_LENGTH", [
			{
				path,
				message: `Field ${path} must be ${expected.join(" or ")} octets, got ${bytes.length}`,
			},
		]);
	}
}

/**
 * Reject a sealed body whose algorithm differs from what the decryptor
 * implements.
 */
function requireAlgorithm(sealed: EncryptedBody, expectedOid: string): void {
	if (sealed.algorithmOid !== expectedOid) {
		throw new ValidationError("ALGORITHM_MISMATCH", [
			{
				path: "sealed.algorithmOid",
				message: `Sealed with ${sealed.algorithmOid}, but this decryptor opens ${expectedOid}`,
			},
		]);
	}
}

/**
 * Read {@link EncryptedBody} fields from a wasm `SealedBody`, then free it.
 */
function takeSealedBody(sealed: {
	algorithmOid: string;
	envelopeDer: Uint8Array;
	ciphertext: Uint8Array;
	free(): void;
}): EncryptedBody {
	try {
		const encryptedBody = {
			algorithmOid: sealed.algorithmOid,
			envelopeDer: sealed.envelopeDer,
			ciphertext: sealed.ciphertext,
		};
		return encryptedBody;
	} finally {
		sealed.free();
	}
}

/**
 * The profile {@link Hasher}: SHA3-256 computed in the wasm module.
 */
export class Sha3_256 implements Hasher {
	/**
	 * Dotted OID of SHA3-256, the profile digest.
	 */
	readonly algorithmOid = PROFILE_OIDS.sha3_256;

	/**
	 * Digest `data` with SHA3-256.
	 */
	digest(data: Uint8Array): Promise<Uint8Array> {
		const digest = WasmSha3_256.digest(data);
		const result = Promise.resolve(digest);
		return result;
	}
}

/**
 * A secp256k1 ECDSA verifying (public) key, for `Frame.verify`.
 */
export class Secp256k1VerifyingKey implements FrameVerifier {
	private constructor(private readonly inner: WasmSecp256k1VerifyingKey) {}

	/**
	 * Wrap a SEC1-encoded point (33-byte compressed or 65-byte uncompressed).
	 *
	 * @throws ValidationError when the encoding length is wrong.
	 */
	static fromSec1Bytes(sec1: Uint8Array): Secp256k1VerifyingKey {
		requireLength(sec1, [33, 65], "sec1");

		const key = new Secp256k1VerifyingKey(
			WasmSecp256k1VerifyingKey.fromSec1Bytes(sec1),
		);
		return key;
	}

	/**
	 * The SEC1-encoded point.
	 */
	toSec1Bytes(): Uint8Array {
		return this.inner.toSec1Bytes();
	}

	/**
	 * Subject-key-identifier octets naming this verifying key.
	 */
	signerId(): Uint8Array {
		return this.inner.signerId();
	}

	/**
	 * Verify a frame under this key (profile ECDSA over SHA3-256).
	 */
	verifyFrame(frame: VerifiableFrame): void {
		this.inner.verifyFrame(frame.toDer());
	}
}

/**
 * The profile {@link Signatory}: a local secp256k1 ECDSA signing key (raw
 * 32-byte scalar) owned by the wasm module.
 */
export class Secp256k1SigningKey implements Signatory {
	/**
	 * Dotted OID of ECDSA with SHA3-256, the profile signature algorithm.
	 */
	readonly signatureAlgorithmOid = PROFILE_OIDS.ecdsaWithSha3_256;

	/**
	 * Dotted OID of SHA3-256, the digest paired with the profile signature.
	 */
	readonly digestAlgorithmOid = PROFILE_OIDS.sha3_256;

	private constructor(private readonly inner: WasmSecp256k1SigningKey) {}

	/**
	 * Wrap a raw 32-byte secp256k1 scalar.
	 *
	 * @throws ValidationError when the scalar length is wrong.
	 */
	static fromBytes(bytes: Uint8Array): Secp256k1SigningKey {
		requireLength(bytes, [32], "bytes");

		const key = new Secp256k1SigningKey(
			WasmSecp256k1SigningKey.fromBytes(bytes),
		);
		return key;
	}

	/**
	 * Derive the verifying key. The wasm module MUST be initialized
	 * (`initClient`).
	 */
	verifyingKey(): Secp256k1VerifyingKey {
		const key = Secp256k1VerifyingKey.fromSec1Bytes(
			this.inner.derivePublicKey(),
		);
		return key;
	}

	/**
	 * Verify half for envelope `signed(this)` / `Frame.verify`.
	 */
	get verifier(): FrameVerifier {
		return this.verifyingKey();
	}

	/**
	 * DER SubjectPublicKeyInfo for this key (uncompressed SEC1).
	 *
	 * Matches Rust profile `EncodePublicKey` / leaf-cert SPKI, so the
	 * octets are safe for CSR enrollment and `TransportSigner.publicKeyDer`.
	 * The wasm module MUST be initialized (`initClient`).
	 */
	toSpkiDer(): Uint8Array {
		return this.inner.toSpkiDer();
	}

	/**
	 * The subject-key-identifier octets naming this signer in the frame.
	 */
	signerId(): Uint8Array {
		return this.inner.signerId();
	}

	/**
	 * Sign `prehash` in the wasm module, with no rehash, resolving with a
	 * DER `ECDSA-Sig-Value`.
	 */
	signPrehash(prehash: Uint8Array): Promise<Uint8Array> {
		const signature = this.inner.signPrehash(prehash);
		const result = Promise.resolve(signature);
		return result;
	}
}

/**
 * The profile symmetric {@link BodyEncryptor} and {@link BodyDecryptor}: a
 * 32-byte shared key-encryption key that wraps a fresh AES-256-GCM content
 * key per seal (RFC 5652 § 6.2.3). The shared key both seals and opens, and
 * every holder names it by one `keyId`.
 */
export class Aes256Gcm implements BodyEncryptor, BodyDecryptor {
	private constructor(private readonly inner: WasmAes256Gcm) {}

	/**
	 * Wrap a raw 32-byte key and the identifier that names it.
	 *
	 * An envelope carries `keyId` in the clear, and an open refuses an
	 * envelope that names another key.
	 *
	 * @throws ValidationError when the key length is wrong or `keyId` is
	 * empty.
	 */
	static fromKey(key: Uint8Array, keyId: Uint8Array): Aes256Gcm {
		requireLength(key, [32], "key");
		if (keyId.length === 0) {
			throw new ValidationError("KEY_ID_REQUIRED", [
				{ path: "keyId", message: "Field keyId must not be empty" },
			]);
		}

		const aes256Gcm = new Aes256Gcm(WasmAes256Gcm.fromKey(key, keyId));
		return aes256Gcm;
	}

	/**
	 * Seal `bodyDer` under a fresh content key.
	 */
	encrypt(bodyDer: Uint8Array, contentOid?: string): Promise<EncryptedBody> {
		const encryptedBody = takeSealedBody(
			this.inner.seal(bodyDer, contentOid),
		);
		const result = Promise.resolve(encryptedBody);
		return result;
	}

	/**
	 * Open a body sealed with this key.
	 *
	 * @throws ValidationError when the sealed algorithm is not AES-256-GCM.
	 */
	async decrypt(sealed: EncryptedBody): Promise<Uint8Array> {
		requireAlgorithm(sealed, PROFILE_OIDS.aes256Gcm);

		const plaintext = await this.inner.open(
			sealed.envelopeDer,
			sealed.ciphertext,
		);
		return plaintext;
	}
}

/**
 * The profile asymmetric {@link BodyEncryptor}: HPKE to a recipient public
 * key (DHKEM over secp256k1 with an AES-256-GCM content key, in a CMS
 * `KEMRecipientInfo`). Only the holder of the matching secret key can open
 * the body.
 *
 * # Sources
 *
 * - RFC 9180, Hybrid Public Key Encryption:
 *   {@link https://datatracker.ietf.org/doc/html/rfc9180 RFC 9180}
 * - RFC 9629, Using Key Encapsulation Mechanism (KEM) Algorithms in CMS:
 *   {@link https://datatracker.ietf.org/doc/html/rfc9629 RFC 9629}
 */
export class HpkeEncryptor implements BodyEncryptor {
	private constructor(private readonly inner: WasmHpkeEncryptor) {}

	/**
	 * Wrap the recipient's SEC1-encoded public key (33-byte compressed or
	 * 65-byte uncompressed).
	 *
	 * @throws ValidationError when the encoding length is wrong.
	 */
	static fromBytes(recipientPublicKey: Uint8Array): HpkeEncryptor {
		requireLength(recipientPublicKey, [33, 65], "recipientPublicKey");

		const encryptor = new HpkeEncryptor(
			WasmHpkeEncryptor.fromBytes(recipientPublicKey),
		);
		return encryptor;
	}

	/**
	 * Seal `bodyDer` to the recipient under a fresh ephemeral key.
	 */
	encrypt(bodyDer: Uint8Array, contentOid?: string): Promise<EncryptedBody> {
		const encryptedBody = takeSealedBody(
			this.inner.seal(bodyDer, contentOid),
		);

		const result = Promise.resolve(encryptedBody);
		return result;
	}
}

/**
 * The matching profile {@link BodyDecryptor} for HPKE-sealed bodies: holds
 * the raw 32-byte recipient secret key.
 */
export class HpkeDecryptor implements BodyDecryptor {
	private constructor(private readonly inner: WasmHpkeDecryptor) {}

	/**
	 * Wrap the raw 32-byte recipient secret key.
	 */
	static fromBytes(secretKey: Uint8Array): HpkeDecryptor {
		requireLength(secretKey, [32], "secretKey");

		const decryptor = new HpkeDecryptor(
			WasmHpkeDecryptor.fromBytes(secretKey),
		);
		return decryptor;
	}

	/**
	 * Open a body sealed to this recipient.
	 *
	 * @throws ValidationError when the sealed algorithm is not AES-256-GCM.
	 */
	async decrypt(sealed: EncryptedBody): Promise<Uint8Array> {
		requireAlgorithm(sealed, PROFILE_OIDS.aes256Gcm);

		const plaintext = await this.inner.open(
			sealed.envelopeDer,
			sealed.ciphertext,
		);
		return plaintext;
	}
}
