/**
 * Cryptographic interfaces and the tightbeam profile implementations.
 */

import {
	derivePublicKey,
	openAes256Gcm,
	openEciesSecp256k1,
	profileSignerId,
	sealAes256Gcm,
	sealEciesSecp256k1,
	sha3_256 as wasmSha3_256,
	signTbs,
} from "#wasm";

import { ValidationError } from "./builder/errors.js";

/**
 * The dotted algorithm OIDs of the tightbeam profile (`tightbeam::oids`).
 */
export const PROFILE_OIDS = {
	/** SHA3-256, the profile digest. */
	sha3_256: "2.16.840.1.101.3.4.2.8",
	/** secp256k1 ECDSA over SHA3-256, the profile signature. */
	ecdsaWithSha3_256: "2.16.840.1.101.3.4.3.10",
	/** AES-256-GCM, the profile symmetric cipher. */
	aes256Gcm: "2.16.840.1.101.3.4.1.46",
	/** ECIES over secp256k1 (HKDF-SHA3-256 + AES-256-GCM). */
	eciesSecp256k1: "1.3.132.1.12.0",
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
 * A sealed frame body: the pieces recorded in the frame's confidentiality
 * info alongside the ciphertext that replaces the body.
 */
export interface EncryptedBody {
	/**
	 * The dotted OID of the encryption algorithm.
	 */
	readonly algorithmOid: string;

	/**
	 * The DER-encoded algorithm parameters (e.g. the nonce), when the
	 * scheme has any.
	 */
	readonly parametersDer?: Uint8Array;

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
	 * Seal `bodyDer`, resolving with the algorithm OID, its parameters,
	 * and the ciphertext.
	 */
	encrypt(bodyDer: Uint8Array): Promise<EncryptedBody>;
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
 * A frame signer. Anything that can produce a signature over the to-be-signed
 * bytes qualifies - a local {@link Secp256k1SigningKey}, wallets, passkeys,
 * HSMs, remote KMS backends. An external signer's private key never enters
 * wasm memory.
 */
export interface Signatory {
	/**
	 * The dotted OID of the signature algorithm this signer implements.
	 */
	readonly signatureAlgorithmOid: string;

	/**
	 * The dotted OID of the digest the signature is computed over.
	 */
	readonly digestAlgorithmOid: string;

	/**
	 * The subject-key-identifier octets naming this signer in the frame.
	 */
	signerId(): Uint8Array;

	/**
	 * Sign the to-be-signed bytes, resolving with the raw signature octets.
	 */
	sign(tbs: Uint8Array): Promise<Uint8Array>;
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
 * The profile {@link Hasher}: SHA3-256 computed in the wasm module.
 */
export class Sha3_256 implements Hasher {
	readonly algorithmOid = PROFILE_OIDS.sha3_256;

	/**
	 * Digest `data` with SHA3-256.
	 */
	digest(data: Uint8Array): Promise<Uint8Array> {
		const digest = wasmSha3_256(data);
		const result = Promise.resolve(digest);
		return result;
	}
}

/**
 * A secp256k1 ECDSA verifying (public) key, for `Frame.verify`.
 */
export class Secp256k1VerifyingKey {
	private constructor(private readonly sec1: Uint8Array) {}

	/**
	 * Wrap a SEC1-encoded point (33-byte compressed or 65-byte uncompressed).
	 *
	 * @throws ValidationError when the encoding length is wrong.
	 */
	static fromSec1Bytes(sec1: Uint8Array): Secp256k1VerifyingKey {
		requireLength(sec1, [33, 65], "sec1");

		const key = new Secp256k1VerifyingKey(sec1);
		return key;
	}

	/**
	 * The SEC1-encoded point.
	 */
	toSec1Bytes(): Uint8Array {
		return this.sec1;
	}
}

/**
 * The profile {@link Signatory}: a local secp256k1 ECDSA signing key (raw
 * 32-byte scalar) signing SHA3-256 digests in the wasm module.
 */
export class Secp256k1SigningKey implements Signatory {
	readonly signatureAlgorithmOid = PROFILE_OIDS.ecdsaWithSha3_256;
	readonly digestAlgorithmOid = PROFILE_OIDS.sha3_256;

	private constructor(private readonly scalar: Uint8Array) {}

	/**
	 * Wrap a raw 32-byte secp256k1 scalar.
	 *
	 * @throws ValidationError when the scalar length is wrong.
	 */
	static fromBytes(bytes: Uint8Array): Secp256k1SigningKey {
		requireLength(bytes, [32], "bytes");

		const key = new Secp256k1SigningKey(bytes);
		return key;
	}

	/**
	 * Derive the verifying key. The wasm module MUST be initialized
	 * (`initClient`).
	 */
	verifyingKey(): Secp256k1VerifyingKey {
		const key = Secp256k1VerifyingKey.fromSec1Bytes(
			derivePublicKey(this.scalar),
		);
		return key;
	}

	/**
	 * The subject-key-identifier octets naming this signer in the frame.
	 */
	signerId(): Uint8Array {
		const publicKey = derivePublicKey(this.scalar);
		const id = profileSignerId(publicKey);
		return id;
	}

	/**
	 * Sign the SHA3-256 digest of `tbs` in the wasm module, resolving with
	 * the raw 64-byte `r || s` signature.
	 */
	sign(tbs: Uint8Array): Promise<Uint8Array> {
		const signature = signTbs(this.scalar, tbs);
		const result = Promise.resolve(signature);
		return result;
	}
}

/**
 * The profile symmetric {@link BodyEncryptor} and {@link BodyDecryptor}:
 * AES-256-GCM under a 32-byte shared key. The shared key both seals and
 * opens.
 */
export class Aes256Gcm implements BodyEncryptor, BodyDecryptor {
	private constructor(private readonly keyBytes: Uint8Array) {}

	/**
	 * Wrap a raw 32-byte key.
	 *
	 * @throws ValidationError when the key length is wrong.
	 */
	static fromKey(key: Uint8Array): Aes256Gcm {
		requireLength(key, [32], "key");

		const aes256Gcm = new Aes256Gcm(key);
		return aes256Gcm;
	}

	/**
	 * Seal `bodyDer` under a fresh nonce.
	 */
	encrypt(bodyDer: Uint8Array): Promise<EncryptedBody> {
		const sealed = sealAes256Gcm(this.keyBytes, bodyDer);
		try {
			const encryptedBody = {
				algorithmOid: sealed.algorithmOid,
				parametersDer: sealed.parametersDer,
				ciphertext: sealed.ciphertext,
			};

			const result = Promise.resolve(encryptedBody);
			return result;
		} finally {
			sealed.free();
		}
	}

	/**
	 * Open a body sealed with this key.
	 *
	 * @throws ValidationError when the sealed algorithm is not AES-256-GCM.
	 */
	async decrypt(sealed: EncryptedBody): Promise<Uint8Array> {
		requireAlgorithm(sealed, PROFILE_OIDS.aes256Gcm);

		const plaintext = openAes256Gcm(
			this.keyBytes,
			sealed.parametersDer,
			sealed.ciphertext,
		);
		return plaintext;
	}
}

/**
 * The profile asymmetric {@link BodyEncryptor}: ECIES to a recipient
 * public key (secp256k1 + HKDF-SHA3-256 + AES-256-GCM). Only the holder of
 * the matching secret key can open the body.
 */
export class EciesEncryptor implements BodyEncryptor {
	private constructor(private readonly recipient: Uint8Array) {}

	/**
	 * Wrap the recipient's SEC1-encoded public key (33-byte compressed or
	 * 65-byte uncompressed).
	 *
	 * @throws ValidationError when the encoding length is wrong.
	 */
	static fromBytes(recipientPublicKey: Uint8Array): EciesEncryptor {
		requireLength(recipientPublicKey, [33, 65], "recipientPublicKey");

		const encryptor = new EciesEncryptor(recipientPublicKey);
		return encryptor;
	}

	/**
	 * Seal `bodyDer` to the recipient under a fresh ephemeral key.
	 */
	encrypt(bodyDer: Uint8Array): Promise<EncryptedBody> {
		const sealed = sealEciesSecp256k1(this.recipient, bodyDer);
		try {
			const encryptedBody = {
				algorithmOid: sealed.algorithmOid,
				parametersDer: sealed.parametersDer,
				ciphertext: sealed.ciphertext,
			};

			const result = Promise.resolve(encryptedBody);
			return result;
		} finally {
			sealed.free();
		}
	}
}

/**
 * The matching profile {@link BodyDecryptor} for ECIES-sealed bodies:
 * holds the raw 32-byte recipient secret key.
 */
export class EciesDecryptor implements BodyDecryptor {
	private constructor(private readonly secret: Uint8Array) {}

	/**
	 * Wrap the raw 32-byte recipient secret key.
	 *
	 * @throws ValidationError when the key length is wrong.
	 */
	static fromBytes(secretKey: Uint8Array): EciesDecryptor {
		requireLength(secretKey, [32], "secretKey");

		const decryptor = new EciesDecryptor(secretKey);
		return decryptor;
	}

	/**
	 * Open a body sealed to this recipient.
	 *
	 * @throws ValidationError when the sealed algorithm is not ECIES.
	 */
	async decrypt(sealed: EncryptedBody): Promise<Uint8Array> {
		requireAlgorithm(sealed, PROFILE_OIDS.eciesSecp256k1);

		const plaintext = openEciesSecp256k1(
			this.secret,
			sealed.parametersDer,
			sealed.ciphertext,
		);
		return plaintext;
	}
}
