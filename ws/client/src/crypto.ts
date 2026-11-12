/**
 * Cryptographic interfaces and the tightbeam profile implementations.
 */

import type {
	Aes256Gcm as WasmAes256Gcm,
	EncryptedBody,
	HpkeSecp256k1Decryptor as WasmHpkeDecryptor,
	HpkeSecp256k1Encryptor as WasmHpkeEncryptor,
	Secp256k1SigningKey as WasmSecp256k1SigningKey,
	Secp256k1VerifyingKey as WasmSecp256k1VerifyingKey,
	SharedKey,
} from "#wasm";

import type { EngineModule, EngineParts } from "./engine.js";
import type { SignatureInfo } from "./frame.js";
import type { OidName } from "./views.js";
import { OidView } from "./views.js";
import { ClientTransportError } from "./errors.js";
import { Owned } from "./owned.js";

export type { EncryptedBody } from "#wasm";

/**
 * A digest capability. Implement it with any hash library.
 */
export interface Hasher {
	/**
	 * The digest algorithm this hasher implements.
	 */
	readonly algorithmOid: OidName;

	/**
	 * Digest `data`, resolving with the raw digest octets.
	 *
	 * @throws any error of the implementation, as a throw or a rejection. It rejects the build, the verdict or the
	 * opening that asked for the digest.
	 */
	readonly digest: (data: Uint8Array) => Promise<Uint8Array>;
}

/**
 * A body-encryption capability. It receives the body that the frame holds at the seal step and returns the sealed
 * pieces. That body is the body DER (the profile opaque body for a raw message), or its compressed octets when the
 * build compresses.
 */
export interface BodyEncryptor {
	/**
	 * Seal `bodyDer`, resolving with its envelope and ciphertext.
	 *
	 * @param contentOid - The content type the envelope authenticates: `id-data` unless the codec or the builder names
	 * another.
	 * @throws any error of the implementation, as a throw or a rejection. It rejects the build.
	 */
	readonly encrypt: (bodyDer: Uint8Array, contentOid: OidName) => Promise<EncryptedBody>;
}

/**
 * The matching body-decryption capability for `Frame.open`. It receives the sealed pieces carried by the frame and
 * resolves with the octets that were sealed: the body DER, or its compressed octets when the frame is compressed.
 */
export interface BodyDecryptor {
	/**
	 * Open `sealed`, resolving with the octets that were sealed.
	 *
	 * @throws any error of the implementation, as a throw or a rejection. It rejects the `Frame.open` that asked for
	 * the plaintext.
	 */
	readonly decrypt: (sealed: EncryptedBody) => Promise<Uint8Array>;
}

/**
 * The frame surface a {@link FrameVerifier} reads, which a frame of the
 * client and a frame of any other implementation both offer.
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
	readonly signatureInfo?: SignatureInfo;
}

/**
 * The verify half of authenticity. The implementation owns the algorithm,
 * such as the profile secp256k1 or an ed25519 key the caller brings, and may
 * verify asynchronously, as WebCrypto does.
 */
export interface FrameVerifier {
	/**
	 * Verify the non-repudiation signature of `frame`.
	 *
	 * @throws when the frame is unsigned, the algorithm differs, or the
	 * signature does not verify, as a throw or as a rejection.
	 */
	readonly verifyFrame: (frame: VerifiableFrame) => void | Promise<void>;
}

/**
 * A frame signer: a local {@link Secp256k1SigningKey}, or a wallet, a passkey,
 * an HSM, or a remote KMS backend that keeps its private key outside wasm. The
 * wasm profile fixes the signature, so a signer signs ECDSA over secp256k1
 * with SHA3-256, and the peer refuses a signature under any other scheme.
 */
export interface Signatory {
	/**
	 * The subject-key-identifier octets naming this signer's certificate in the frame (RFC 7093 § 2 method 1 for a
	 * profile key).
	 *
	 * @throws any error of the implementation, which rejects the build.
	 */
	readonly signerId: () => Uint8Array;

	/**
	 * Sign `prehash` directly, with no rehash, resolving with a DER `ECDSA-Sig-Value` (RFC 3279 § 2.2.3).
	 *
	 * The prehash is the digest of the frame's CMS signed attributes, which bind its to-be-signed bytes
	 * (RFC 5652 § 5.4).
	 *
	 * @throws any error of the implementation, as a throw or a rejection. It rejects the build.
	 */
	readonly signPrehash: (prehash: Uint8Array) => Promise<Uint8Array>;
}

/**
 * A hasher held past the call that received it: the digest of the caller's
 * hasher, under a copy of the algorithm it names, lent as a view. A free of
 * the caller's handle leaves the holder its own, and the holder has no
 * release, so the glue reclaims the copy with it.
 */
export class HeldHasher implements Hasher {
	readonly algorithmOid: OidView;

	readonly #hasher: Hasher;

	constructor(hasher: Hasher) {
		this.algorithmOid = OidView.copyOf(hasher.algorithmOid);
		this.#hasher = hasher;
	}

	digest(data: Uint8Array): Promise<Uint8Array> {
		const digest = this.#hasher.digest(data);
		return digest;
	}
}

/**
 * The profile {@link Hasher}: SHA3-256 computed in the wasm module.
 */
export class Sha3_256 implements Hasher {
	/**
	 * SHA3-256, the profile digest, which the engine of the realm owns.
	 */
	readonly algorithmOid: OidView;

	readonly #hasher: EngineModule["Sha3_256"];

	private constructor(hasher: EngineModule["Sha3_256"], algorithmOid: OidView) {
		this.algorithmOid = algorithmOid;
		this.#hasher = hasher;
	}

	/**
	 * The profile hasher of `hasher`, the glue class, which names its digest
	 * by `algorithmOid`. The engine builds the one hasher of its realm.
	 *
	 * @internal
	 */
	static over(hasher: EngineParts["glue"]["Sha3_256"], algorithmOid: OidView): Sha3_256 {
		const profile = new Sha3_256(hasher, algorithmOid);
		return profile;
	}

	/**
	 * Digest `data` with SHA3-256.
	 *
	 * @throws TightbeamTransportError `InvalidBytes`, as a rejection, when
	 * `data` is not a `Uint8Array`.
	 */
	async digest(data: Uint8Array): Promise<Uint8Array> {
		const digest = this.#hasher.digest(data);
		return digest;
	}
}

/**
 * The verify half of a secp256k1 ECDSA key, read through the hold of the key
 * that owns its wasm handle. A {@link Secp256k1VerifyingKey} owns its hold,
 * and the view that {@link Secp256k1SigningKey.verifyingKey} lends reads the
 * hold of that signing key, which frees the view with itself.
 */
export class VerifyingKeyView implements FrameVerifier {
	/**
	 * The hold of the wasm verifying key, which its owner releases.
	 */
	protected readonly hold: Owned<WasmSecp256k1VerifyingKey>;

	/**
	 * A view over `hold`, which the key that built it owns.
	 */
	constructor(hold: Owned<WasmSecp256k1VerifyingKey>) {
		this.hold = hold;
	}

	/**
	 * The SEC1-encoded point.
	 *
	 * @throws TightbeamTransportError `KeyReleased` once the owner released
	 * the key.
	 */
	toSec1Bytes(): Uint8Array {
		const key = this.hold.use("toSec1Bytes");
		const sec1 = key.toSec1Bytes();
		return sec1;
	}

	/**
	 * Subject-key-identifier octets naming this verifying key.
	 *
	 * @throws TightbeamTransportError as {@link toSec1Bytes} does.
	 */
	signerId(): Uint8Array {
		const key = this.hold.use("signerId");
		const signerId = key.signerId();
		return signerId;
	}

	/**
	 * Verify a frame under this key (profile ECDSA over SHA3-256).
	 *
	 * @throws TightbeamTransportError as {@link toSec1Bytes} does.
	 */
	verifyFrame(frame: VerifiableFrame): void {
		const key = this.hold.use("verifyFrame");
		const der = frame.toDer();
		key.verifyFrame(der);
	}
}

/**
 * A secp256k1 ECDSA verifying (public) key, for `Frame.verify`, which owns
 * its wasm handle.
 */
export class Secp256k1VerifyingKey extends VerifyingKeyView implements Disposable {
	private constructor(hold: Owned<WasmSecp256k1VerifyingKey>) {
		super(hold);
	}

	/**
	 * Wrap a SEC1-encoded point (33-byte compressed or 65-byte uncompressed)
	 * through the engine `parts`.
	 *
	 * @throws TightbeamTransportError `InvalidVerifyingKey` when the octets
	 * name no secp256k1 point.
	 *
	 * @internal
	 */
	static fromSec1Bytes(parts: EngineParts, sec1: Uint8Array): Secp256k1VerifyingKey {
		const inner = parts.glue.Secp256k1VerifyingKey.fromSec1Bytes(sec1);

		const hold = new Owned(inner, ClientTransportError.keyReleased);
		const key = new Secp256k1VerifyingKey(hold);
		return key;
	}

	/**
	 * Free the wasm handle of the key. The release is idempotent, and every later call on the key refuses with
	 * `KeyReleased`.
	 */
	[Symbol.dispose](): void {
		this.hold[Symbol.dispose]();
	}
}

/**
 * The one verifying key of a signing key: its hold, which the signing key
 * frees, and the view the signing key lends.
 */
interface LentVerifyingKey {
	readonly hold: Owned<WasmSecp256k1VerifyingKey>;
	readonly view: VerifyingKeyView;
}

/**
 * The profile {@link Signatory}: a local secp256k1 ECDSA signing key (raw
 * 32-byte scalar) owned by the wasm module.
 */
export class Secp256k1SigningKey implements Signatory, Disposable {
	readonly #hold: Owned<WasmSecp256k1SigningKey>;

	/**
	 * The verifying-key class of the module that holds this key.
	 */
	readonly #verifyingKeys: EngineModule["Secp256k1VerifyingKey"];

	/**
	 * The one verifying key, derived on first use and freed with this key.
	 */
	#verifying: LentVerifyingKey | undefined;

	private constructor(hold: Owned<WasmSecp256k1SigningKey>, verifyingKeys: EngineModule["Secp256k1VerifyingKey"]) {
		this.#hold = hold;
		this.#verifyingKeys = verifyingKeys;
	}

	/**
	 * Wrap a raw 32-byte secp256k1 scalar through the engine `parts`.
	 *
	 * @throws TightbeamTransportError `InvalidSigningKey` when the scalar is
	 * not 32 octets, or names no key.
	 *
	 * @internal
	 */
	static fromBytes(parts: EngineParts, bytes: Uint8Array): Secp256k1SigningKey {
		const glue = parts.glue;
		const inner = glue.Secp256k1SigningKey.fromBytes(bytes);
		const hold = new Owned(inner, ClientTransportError.keyReleased);

		const key = new Secp256k1SigningKey(hold, glue.Secp256k1VerifyingKey);
		return key;
	}

	/**
	 * The verifying key, derived on the first call and lent by this key, which
	 * frees it with itself. Every call answers the same view.
	 *
	 * @throws TightbeamTransportError `KeyReleased` when this key was released.
	 */
	verifyingKey(): VerifyingKeyView {
		const signing = this.#hold.use("verifyingKey");
		const lent = this.#verifying;
		if (lent !== undefined) {
			return lent.view;
		}

		const sec1 = signing.derivePublicKey();
		const inner = this.#verifyingKeys.fromSec1Bytes(sec1);

		const hold = new Owned(inner, ClientTransportError.keyReleased);
		const view = new VerifyingKeyView(hold);
		this.#verifying = { hold, view };

		return view;
	}

	/**
	 * DER SubjectPublicKeyInfo for this key (uncompressed SEC1).
	 *
	 * Matches Rust profile `EncodePublicKey` / leaf-cert SPKI, so the
	 * octets are safe for CSR enrollment and `TransportSigner.publicKeyDer`.
	 */
	toSpkiDer(): Uint8Array {
		const signing = this.#hold.use("toSpkiDer");
		const spki = signing.toSpkiDer();
		return spki;
	}

	/**
	 * The subject-key-identifier octets naming this signer in the frame.
	 */
	signerId(): Uint8Array {
		const signing = this.#hold.use("signerId");
		const signerId = signing.signerId();
		return signerId;
	}

	/**
	 * Sign `prehash` in the wasm module, with no rehash, resolving with a
	 * DER `ECDSA-Sig-Value`.
	 *
	 * @throws TightbeamTransportError, as a rejection, `KeyReleased` once the
	 * key is released and `InvalidPrehash` when the key cannot sign `prehash`.
	 */
	async signPrehash(prehash: Uint8Array): Promise<Uint8Array> {
		const signing = this.#hold.use("signPrehash");
		const signature = signing.signPrehash(prehash);
		return signature;
	}

	/**
	 * Release the scalar and the verifying key: the wasm copy of the scalar wipes now. The release is idempotent, and
	 * every later call on this key, or on the verifying key it lent, refuses with `KeyReleased`.
	 */
	[Symbol.dispose](): void {
		this.#verifying?.hold[Symbol.dispose]();
		this.#hold[Symbol.dispose]();
	}
}

/**
 * The profile symmetric {@link BodyEncryptor} and {@link BodyDecryptor}: a
 * 32-byte shared key-encryption key that wraps a fresh AES-256-GCM content
 * key per seal (RFC 5652 § 6.2.3). The shared key both seals and opens, and
 * every holder names it by one `keyId`.
 */
export class Aes256Gcm implements BodyEncryptor, BodyDecryptor, Disposable {
	readonly #hold: Owned<WasmAes256Gcm>;

	private constructor(hold: Owned<WasmAes256Gcm>) {
		this.#hold = hold;
	}

	/**
	 * Wrap a raw 32-byte key and the `keyId` that names it, which an envelope
	 * carries in the clear, through the engine `parts`.
	 *
	 * @throws TightbeamTransportError at the field it names on `path`:
	 * `EmptyKeyId`, `KeyError` for a key of another length, or `InvalidBytes`.
	 *
	 * @internal
	 */
	static fromKey(parts: EngineParts, shared: SharedKey): Aes256Gcm {
		const inner = parts.glue.Aes256Gcm.fromKey(shared);
		const hold = new Owned(inner, ClientTransportError.keyReleased);

		const aes256Gcm = new Aes256Gcm(hold);
		return aes256Gcm;
	}

	/**
	 * Seal `bodyDer` under a fresh content key.
	 *
	 * @throws TightbeamTransportError `KeyReleased`, as a rejection, once the
	 * key is released.
	 */
	async encrypt(bodyDer: Uint8Array, contentOid: OidName): Promise<EncryptedBody> {
		const cipher = this.#hold.use("encrypt");
		using content = contentOid.clone();

		const sealed = cipher.seal(bodyDer, content);
		const encryptedBody = sealed.takePieces();
		return encryptedBody;
	}

	/**
	 * Open a body sealed with this key, under the algorithm and the key that
	 * its envelope names.
	 *
	 * @throws TightbeamTransportError, as a rejection, `KeyReleased` once the
	 * key is released, and the refusal of the engine otherwise.
	 */
	async decrypt(sealed: EncryptedBody): Promise<Uint8Array> {
		const cipher = this.#hold.use("decrypt");
		const plaintext = await cipher.open(sealed);
		return plaintext;
	}

	/**
	 * Release the shared key. The wasm copy wipes at once, or when an open already in flight settles. The release is
	 * idempotent, and every later call on this cipher refuses with `KeyReleased`.
	 */
	[Symbol.dispose](): void {
		this.#hold[Symbol.dispose]();
	}
}

/**
 * The profile asymmetric {@link BodyEncryptor}: HPKE (RFC 9180) to a recipient
 * public key, with DHKEM over secp256k1 and an AES-256-GCM content key in a
 * CMS `KEMRecipientInfo` (RFC 9629). The holder of the matching secret key
 * alone opens the body.
 */
export class HpkeEncryptor implements BodyEncryptor, Disposable {
	readonly #hold: Owned<WasmHpkeEncryptor>;

	private constructor(hold: Owned<WasmHpkeEncryptor>) {
		this.#hold = hold;
	}

	/**
	 * Wrap the recipient's SEC1-encoded public key (33-byte compressed or
	 * 65-byte uncompressed) through the engine `parts`.
	 *
	 * @throws TightbeamTransportError `InvalidVerifyingKey` when the octets
	 * name no secp256k1 point.
	 *
	 * @internal
	 */
	static fromBytes(parts: EngineParts, recipientPublicKey: Uint8Array): HpkeEncryptor {
		const encryptors = parts.glue.HpkeSecp256k1Encryptor;
		const inner = encryptors.fromBytes(recipientPublicKey);
		const hold = new Owned(inner, ClientTransportError.keyReleased);

		const encryptor = new HpkeEncryptor(hold);
		return encryptor;
	}

	/**
	 * Seal `bodyDer` to the recipient under a fresh ephemeral key.
	 *
	 * @throws TightbeamTransportError `KeyReleased`, as a rejection, once the
	 * key is released.
	 */
	async encrypt(bodyDer: Uint8Array, contentOid: OidName): Promise<EncryptedBody> {
		const recipient = this.#hold.use("encrypt");
		using content = contentOid.clone();

		const sealed = recipient.seal(bodyDer, content);
		const encryptedBody = sealed.takePieces();
		return encryptedBody;
	}

	/**
	 * Free the wasm handle of the recipient key. The release is idempotent, and every later call on this encryptor
	 * refuses with `KeyReleased`.
	 */
	[Symbol.dispose](): void {
		this.#hold[Symbol.dispose]();
	}
}

/**
 * The matching profile {@link BodyDecryptor} for HPKE-sealed bodies: holds
 * the raw 32-byte recipient secret key.
 */
export class HpkeDecryptor implements BodyDecryptor, Disposable {
	readonly #hold: Owned<WasmHpkeDecryptor>;

	private constructor(hold: Owned<WasmHpkeDecryptor>) {
		this.#hold = hold;
	}

	/**
	 * Wrap the raw 32-byte recipient secret key through the engine `parts`.
	 *
	 * @throws TightbeamTransportError `InvalidSigningKey` when the secret is
	 * not 32 octets, or names no key.
	 *
	 * @internal
	 */
	static fromBytes(parts: EngineParts, secretKey: Uint8Array): HpkeDecryptor {
		const inner = parts.glue.HpkeSecp256k1Decryptor.fromBytes(secretKey);
		const hold = new Owned(inner, ClientTransportError.keyReleased);

		const decryptor = new HpkeDecryptor(hold);
		return decryptor;
	}

	/**
	 * Open a body sealed to this recipient, under the algorithm and the
	 * recipient that its envelope names.
	 *
	 * @throws TightbeamTransportError, as a rejection, `KeyReleased` once the
	 * key is released, and the refusal of the engine otherwise.
	 */
	async decrypt(sealed: EncryptedBody): Promise<Uint8Array> {
		const recipient = this.#hold.use("decrypt");
		const plaintext = await recipient.open(sealed);
		return plaintext;
	}

	/**
	 * Release the recipient secret. The wasm copy wipes at once, or when an open already in flight settles. The release
	 * is idempotent, and every later call on this decryptor refuses with `KeyReleased`.
	 */
	[Symbol.dispose](): void {
		this.#hold[Symbol.dispose]();
	}
}
