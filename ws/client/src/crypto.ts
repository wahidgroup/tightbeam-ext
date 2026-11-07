/**
 * Cryptographic interfaces and the tightbeam profile implementations.
 */

import type {
	Aes256Gcm as WasmAes256Gcm,
	EncryptedBody,
	HpkeSecp256k1Decryptor as WasmHpkeDecryptor,
	HpkeSecp256k1Encryptor as WasmHpkeEncryptor,
	Oid,
	SealedBody,
	Secp256k1SigningKey as WasmSecp256k1SigningKey,
	Secp256k1VerifyingKey as WasmSecp256k1VerifyingKey,
	SharedKey,
} from "#wasm";

import type { EngineModule } from "./engine.js";
import type { SignatureInfo } from "./frame.js";
import type { OidName } from "./views.js";
import { Lent, OidView } from "./views.js";
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
	 */
	digest(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * A body-encryption capability. It receives the body DER (the profile opaque
 * body for a raw message) and returns the sealed pieces.
 */
export interface BodyEncryptor {
	/**
	 * Seal `bodyDer`, resolving with its envelope and ciphertext.
	 *
	 * @param contentOid - The content type the envelope authenticates:
	 * `id-data` unless the codec or the builder names another.
	 */
	encrypt(bodyDer: Uint8Array, contentOid: OidName): Promise<EncryptedBody>;
}

/**
 * The matching body-decryption capability for `Frame.open`. It receives the
 * sealed pieces carried by the frame and resolves with the plaintext body
 * DER.
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
	readonly signatureInfo?: SignatureInfo;
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
 * A frame signer: a local {@link Secp256k1SigningKey}, a wallet, a passkey,
 * an HSM, or a remote KMS backend. An external signer's private key never
 * enters wasm memory.
 *
 * - The engine owns the signature profile: a frame carries a CMS `SignerInfo`
 *   whose form the wasm profile fixes.
 * - A signer therefore signs ECDSA over secp256k1 with SHA3-256. A signature
 *   under any other scheme fails verification at the peer.
 */
export interface Signatory {
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

	private constructor(
		hasher: EngineModule["Sha3_256"],
		algorithmOid: OidView,
	) {
		this.algorithmOid = algorithmOid;
		this.#hasher = hasher;
	}

	/**
	 * The profile hasher of `hasher`, the glue class, which names its digest
	 * by `algorithmOid`.
	 */
	static over(
		hasher: EngineModule["Sha3_256"],
		algorithmOid: OidView,
	): Sha3_256 {
		const profile = new Sha3_256(hasher, algorithmOid);
		return profile;
	}

	/**
	 * Digest `data` with SHA3-256.
	 */
	digest(data: Uint8Array): Promise<Uint8Array> {
		const digest = this.#hasher.digest(data);
		const result = Promise.resolve(digest);
		return result;
	}
}

/**
 * The verify half of a secp256k1 ECDSA key, read through the hold of the key
 * that owns its wasm handle.
 *
 * A {@link Secp256k1VerifyingKey} owns its own hold and releases it. The view
 * that {@link Secp256k1SigningKey.verifyingKey} lends reads the hold of that
 * signing key, which frees it with itself, so the view has no release.
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
export class Secp256k1VerifyingKey
	extends VerifyingKeyView
	implements Disposable
{
	private constructor(hold: Owned<WasmSecp256k1VerifyingKey>) {
		super(hold);
	}

	/**
	 * Wrap a SEC1-encoded point (33-byte compressed or 65-byte uncompressed)
	 * in the module `glue`.
	 *
	 * @throws TightbeamTransportError `InvalidVerifyingKey` when the octets
	 * name no secp256k1 point.
	 */
	static fromSec1Bytes(
		glue: EngineModule,
		sec1: Uint8Array,
	): Secp256k1VerifyingKey {
		const inner = glue.Secp256k1VerifyingKey.fromSec1Bytes(sec1);

		const hold = new Owned(inner, ClientTransportError.keyReleased);
		const key = new Secp256k1VerifyingKey(hold);
		return key;
	}

	/**
	 * Free the wasm handle of the key. A later release does nothing, and
	 * every later call on the key refuses with `KeyReleased`.
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

	private constructor(
		hold: Owned<WasmSecp256k1SigningKey>,
		verifyingKeys: EngineModule["Secp256k1VerifyingKey"],
	) {
		this.#hold = hold;
		this.#verifyingKeys = verifyingKeys;
	}

	/**
	 * Wrap a raw 32-byte secp256k1 scalar in the module `glue`.
	 *
	 * @throws TightbeamTransportError `InvalidSigningKey` when the scalar is
	 * not 32 octets, or names no key.
	 */
	static fromBytes(
		glue: EngineModule,
		bytes: Uint8Array,
	): Secp256k1SigningKey {
		const inner = glue.Secp256k1SigningKey.fromBytes(bytes);
		const hold = new Owned(inner, ClientTransportError.keyReleased);

		const key = new Secp256k1SigningKey(hold, glue.Secp256k1VerifyingKey);
		return key;
	}

	/**
	 * The verifying key, derived on the first call and lent by this key,
	 * which frees it with itself. Every call answers the same view, and the
	 * view has no release of its own.
	 *
	 * @throws TightbeamTransportError `KeyReleased` when this key was
	 * released before the first call.
	 */
	verifyingKey(): VerifyingKeyView {
		const lent = this.#verifying;
		if (lent !== undefined) {
			return lent.view;
		}

		const signing = this.#hold.use("verifyingKey");
		const sec1 = signing.derivePublicKey();
		const inner = this.#verifyingKeys.fromSec1Bytes(sec1);

		const hold = new Owned(inner, ClientTransportError.keyReleased);
		const view = new VerifyingKeyView(hold);
		this.#verifying = { hold, view };
		return view;
	}

	/**
	 * Verify half for envelope `signed(this)` / `Frame.verify`: the one
	 * verifying key of {@link verifyingKey}.
	 */
	get verifier(): FrameVerifier {
		return this.verifyingKey();
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
	 */
	signPrehash(prehash: Uint8Array): Promise<Uint8Array> {
		const signing = this.#hold.use("signPrehash");
		const signature = signing.signPrehash(prehash);

		const result = Promise.resolve(signature);
		return result;
	}

	/**
	 * Release the scalar and the verifying key: the wasm copy of the scalar
	 * wipes now. A later release does nothing, and every later call on this
	 * key, or on the verifying key it lent, refuses with `KeyReleased`.
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
	 * Wrap a raw 32-byte key and the identifier that names it, each in a field
	 * of its own name, in the module `glue`. An envelope carries `keyId` in the
	 * clear, and an open refuses an envelope that names another key.
	 *
	 * @throws TightbeamTransportError, with the field on `path`:
	 *
	 * - `EmptyKeyId` at `shared.keyId` when `keyId` is empty.
	 * - `KeyError` at `shared.key` when the key is not 32 octets.
	 * - `InvalidBytes` when a member is no `Uint8Array`.
	 */
	static fromKey(glue: EngineModule, shared: SharedKey): Aes256Gcm {
		const inner = glue.Aes256Gcm.fromKey(shared);
		const hold = new Owned(inner, ClientTransportError.keyReleased);

		const aes256Gcm = new Aes256Gcm(hold);
		return aes256Gcm;
	}

	/**
	 * Seal `bodyDer` under a fresh content key.
	 */
	encrypt(bodyDer: Uint8Array, contentOid: OidName): Promise<EncryptedBody> {
		const cipher = this.#hold.use("encrypt");
		const seal = (content: Oid): SealedBody =>
			cipher.seal(bodyDer, content);
		const sealed = Lent.oid(contentOid, seal);
		const encryptedBody = sealed.takePieces();

		const result = Promise.resolve(encryptedBody);
		return result;
	}

	/**
	 * Open a body sealed with this key. The engine reads the algorithm and
	 * the key the envelope names, and refuses an envelope this key does not
	 * open.
	 */
	async decrypt(sealed: EncryptedBody): Promise<Uint8Array> {
		const cipher = this.#hold.use("decrypt");
		const plaintext = await cipher.open(sealed);
		return plaintext;
	}

	/**
	 * Release the shared key. The wasm copy wipes at once, or when an open
	 * already in flight settles. A later release does nothing, and every
	 * later call on this cipher refuses with `KeyReleased`.
	 */
	[Symbol.dispose](): void {
		this.#hold[Symbol.dispose]();
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
export class HpkeEncryptor implements BodyEncryptor, Disposable {
	readonly #hold: Owned<WasmHpkeEncryptor>;

	private constructor(hold: Owned<WasmHpkeEncryptor>) {
		this.#hold = hold;
	}

	/**
	 * Wrap the recipient's SEC1-encoded public key (33-byte compressed or
	 * 65-byte uncompressed) in the module `glue`.
	 *
	 * @throws TightbeamTransportError `InvalidVerifyingKey` when the octets
	 * name no secp256k1 point.
	 */
	static fromBytes(
		glue: EngineModule,
		recipientPublicKey: Uint8Array,
	): HpkeEncryptor {
		const inner = glue.HpkeSecp256k1Encryptor.fromBytes(recipientPublicKey);
		const hold = new Owned(inner, ClientTransportError.keyReleased);

		const encryptor = new HpkeEncryptor(hold);
		return encryptor;
	}

	/**
	 * Seal `bodyDer` to the recipient under a fresh ephemeral key.
	 */
	encrypt(bodyDer: Uint8Array, contentOid: OidName): Promise<EncryptedBody> {
		const recipient = this.#hold.use("encrypt");
		const seal = (content: Oid): SealedBody =>
			recipient.seal(bodyDer, content);
		const sealed = Lent.oid(contentOid, seal);
		const encryptedBody = sealed.takePieces();

		const result = Promise.resolve(encryptedBody);
		return result;
	}

	/**
	 * Free the wasm handle of the recipient key. A later release does
	 * nothing, and every later call on this encryptor refuses with
	 * `KeyReleased`.
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
	 * Wrap the raw 32-byte recipient secret key in the module `glue`.
	 *
	 * @throws TightbeamTransportError `InvalidSigningKey` when the secret is
	 * not 32 octets, or names no key.
	 */
	static fromBytes(glue: EngineModule, secretKey: Uint8Array): HpkeDecryptor {
		const inner = glue.HpkeSecp256k1Decryptor.fromBytes(secretKey);
		const hold = new Owned(inner, ClientTransportError.keyReleased);

		const decryptor = new HpkeDecryptor(hold);
		return decryptor;
	}

	/**
	 * Open a body sealed to this recipient. The engine reads the algorithm
	 * and the recipient the envelope names, and refuses an envelope this key
	 * does not open.
	 */
	async decrypt(sealed: EncryptedBody): Promise<Uint8Array> {
		const recipient = this.#hold.use("decrypt");
		const plaintext = await recipient.open(sealed);
		return plaintext;
	}

	/**
	 * Release the recipient secret. The wasm copy wipes at once, or when an
	 * open already in flight settles. A later release does nothing, and every
	 * later call on this decryptor refuses with `KeyReleased`.
	 */
	[Symbol.dispose](): void {
		this.#hold[Symbol.dispose]();
	}
}
