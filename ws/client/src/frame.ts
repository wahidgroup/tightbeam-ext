/**
 * The TypeScript mirror of Rust's `Frame`: a decoded tightbeam frame with
 * its metadata, carried security infos, and verification methods.
 *
 * Verification is algorithm-agile: the verdict methods recompute digests
 * with any {@link Hasher}, and the preimage accessors ({@link Frame.tbs},
 * {@link Frame.witnessInput}, {@link Frame.commitmentInput}) expose the
 * exact bytes to check signatures and digests with any external library.
 */

import type { FrameView } from "#wasm";
import {
	bodyPreimage,
	commitmentPreimage,
	decodeBody,
	inspectFrame,
	tbsBytes,
	verifySignature as wasmVerifySignature,
	witnessInput as wasmWitnessInput,
} from "#wasm";

import type { MessagePriority } from "./builder/priority.js";
import type { Version } from "./builder/version.js";
import type { BodyDecryptor, Hasher, Secp256k1VerifyingKey } from "./crypto.js";
import { ValidationError } from "./builder/errors.js";
import { priorityFromOrdinal } from "./builder/priority.js";
import { versionFromOrdinal } from "./builder/version.js";
import { Sha3_256 } from "./crypto.js";
import { InternalError } from "./errors.js";

/**
 * The integrity-check outcomes, mirroring Rust's `IntegrityVerdict`.
 */
export const INTEGRITY_VERDICTS = [
	"verified",
	"absent",
	"algorithm-mismatch",
	"mismatch",
] as const;

/**
 * An integrity-check outcome. Only `"verified"` means the check passed;
 * `"absent"` distinguishes a frame that carries nothing to check.
 */
export type IntegrityVerdict = (typeof INTEGRITY_VERDICTS)[number];

/**
 * A digest carried by a frame: the algorithm that produced it and the raw
 * octets, mirroring the ASN.1 `DigestInfo`.
 */
export interface DigestInfo {
	/**
	 * Dotted OID of the digest algorithm.
	 */
	readonly algorithmOid: string;
	/**
	 * The raw digest octets produced by `algorithmOid`.
	 */
	readonly digest: Uint8Array;
}

/**
 * A link to a parent frame by the digest of its content (V2+), mirroring
 * the `previousFrame` metadata field.
 */
export type PreviousFrame = DigestInfo;

/**
 * The confidentiality info carried by an encrypted frame: how the body
 * ciphertext was produced.
 */
export interface ConfidentialityInfo {
	/**
	 * Dotted OID of the body-encryption algorithm.
	 */
	readonly algorithmOid: string;
	/**
	 * The DER-encoded algorithm parameters (e.g. the nonce), when the
	 * scheme has any.
	 */
	readonly parametersDer?: Uint8Array;
}

/**
 * The non-repudiation signature carried by a signed frame.
 */
export interface SignatureInfo {
	/**
	 * Dotted OID of the signature algorithm.
	 */
	readonly algorithmOid: string;
	/**
	 * Dotted OID of the digest the signature is computed over.
	 */
	readonly digestAlgorithmOid: string;
	/**
	 * The raw signature octets. Verify them over {@link Frame.tbs} with the
	 * library of your choice, or use {@link Frame.verify} for the profile
	 * scheme.
	 */
	readonly signature: Uint8Array;
}

/**
 * An N×N control matrix (V3+), stored row-major as exactly `n * n` octets.
 */
export interface FrameMatrix {
	/**
	 * Dimension N, in `1..=255`.
	 */
	readonly n: number;
	/**
	 * Row-major bytes of length `n * n`.
	 */
	readonly data: Uint8Array;
}

/**
 * The decoded fields copied out of the wasm view.
 */
interface FrameFields {
	readonly version: Version;
	readonly id: Uint8Array;
	readonly order: bigint;
	readonly body: Uint8Array;
	readonly priority: MessagePriority | undefined;
	readonly lifetime: bigint | undefined;
	readonly previousFrame: PreviousFrame | undefined;
	readonly matrix: FrameMatrix | undefined;
	readonly messageIntegrity: DigestInfo | undefined;
	readonly frameIntegrity: DigestInfo | undefined;
	readonly confidentiality: ConfidentialityInfo | undefined;
	readonly signature: SignatureInfo | undefined;
}

/**
 * Pair an algorithm OID with its digest octets, when both are present.
 */
function digestInfoFrom(
	algorithmOid: string | undefined,
	digest: Uint8Array | undefined,
): DigestInfo | undefined {
	if (algorithmOid === undefined || digest === undefined) {
		return undefined;
	}

	return { algorithmOid, digest };
}

/**
 * Copy the control matrix out of the wasm view, when present.
 */
function matrixOf(view: FrameView): FrameMatrix | undefined {
	const n = view.matrixN;
	const data = view.matrixData;
	if (n === undefined || data === undefined) {
		return undefined;
	}

	return { n, data };
}

/**
 * Copy the confidentiality info out of the wasm view, when present.
 */
function confidentialityOf(view: FrameView): ConfidentialityInfo | undefined {
	const algorithmOid = view.confidentialityAlgorithmOid;
	if (algorithmOid === undefined) {
		return undefined;
	}

	return { algorithmOid, parametersDer: view.confidentialityParametersDer };
}

/**
 * Copy the signature info out of the wasm view, when present.
 */
function signatureOf(view: FrameView): SignatureInfo | undefined {
	const algorithmOid = view.signatureAlgorithmOid;
	const digestAlgorithmOid = view.signatureDigestAlgorithmOid;
	const signature = view.signature;
	if (
		algorithmOid === undefined ||
		digestAlgorithmOid === undefined ||
		signature === undefined
	) {
		return undefined;
	}

	return { algorithmOid, digestAlgorithmOid, signature };
}

/**
 * Copy a wasm {@link FrameView} into plain {@link FrameFields}.
 */
function fieldsOf(view: FrameView): FrameFields {
	const version = versionFromOrdinal(view.version);
	if (version === undefined) {
		throw new InternalError(
			"UNKNOWN_VERSION",
			`the wasm module returned an unknown version ordinal: ${view.version}`,
		);
	}

	let priority: MessagePriority | undefined = undefined;
	const priorityOrdinal = view.priority;
	if (priorityOrdinal !== undefined) {
		priority = priorityFromOrdinal(priorityOrdinal);
		if (priority === undefined) {
			throw new InternalError(
				"UNKNOWN_PRIORITY",
				`the wasm module returned an unknown priority ordinal: ${priorityOrdinal}`,
			);
		}
	}

	return {
		version,
		id: view.id,
		order: view.order,
		body: view.body,
		priority,
		lifetime: view.lifetime,
		previousFrame: digestInfoFrom(
			view.previousHashAlgorithmOid,
			view.previousHashDigest,
		),
		matrix: matrixOf(view),
		messageIntegrity: digestInfoFrom(
			view.messageIntegrityAlgorithmOid,
			view.messageIntegrityDigest,
		),
		frameIntegrity: digestInfoFrom(
			view.frameIntegrityAlgorithmOid,
			view.frameIntegrityDigest,
		),
		confidentiality: confidentialityOf(view),
		signature: signatureOf(view),
	};
}

/**
 * Constant-time-ish byte equality for digest comparison.
 */
function digestsEqual(left: Uint8Array, right: Uint8Array): boolean {
	if (left.length !== right.length) {
		return false;
	}

	let difference = 0;
	for (let index = 0; index < left.length; index += 1) {
		difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
	}

	return difference === 0;
}

/**
 * Check a recomputable digest against a carried one, mirroring Rust's
 * `IntegrityVerdict` semantics.
 */
async function verdictOf(
	carried: DigestInfo | undefined,
	hasher: Hasher,
	preimage: () => Uint8Array,
): Promise<IntegrityVerdict> {
	if (carried === undefined) {
		return "absent";
	}

	if (carried.algorithmOid !== hasher.algorithmOid) {
		return "algorithm-mismatch";
	}

	const recomputed = await hasher.digest(preimage());
	if (digestsEqual(recomputed, carried.digest)) {
		return "verified";
	}

	return "mismatch";
}

/**
 * A tightbeam frame, mirroring Rust's `Frame`.
 *
 * Construct one from received bytes with {@link Frame.fromDer} or from the
 * fluent builder's `build()`. Metadata getters decode the frame lazily on
 * first access.
 *
 * The wasm module MUST be initialized (`initClient`) before any getter or
 * method other than {@link Frame.toDer} is used.
 */
export class Frame {
	private fields: FrameFields | undefined;

	private constructor(private readonly der: Uint8Array) {}

	/**
	 * Wrap a frame DER, mirroring Rust `Frame::from_der`. Decoding is lazy:
	 * structurally invalid bytes throw on first metadata access, not here.
	 */
	static fromDer(der: Uint8Array): Frame {
		return new Frame(der);
	}

	/**
	 * The frame DER, mirroring Rust `Frame::to_der`.
	 */
	toDer(): Uint8Array {
		return this.der;
	}

	/**
	 * Decode and cache the frame fields.
	 *
	 * @throws InternalError when the bytes are not a well-formed frame.
	 */
	private decoded(): FrameFields {
		if (this.fields !== undefined) {
			return this.fields;
		}

		const view = inspectFrame(this.der);
		try {
			this.fields = fieldsOf(view);
		} finally {
			view.free();
		}

		return this.fields;
	}

	/**
	 * Protocol version.
	 */
	get version(): Version {
		return this.decoded().version;
	}

	/**
	 * Opaque message identifier.
	 */
	get id(): Uint8Array {
		return this.decoded().id;
	}

	/**
	 * Monotonic order (Unix seconds).
	 */
	get order(): bigint {
		return this.decoded().order;
	}

	/**
	 * Opaque message body. When {@link confidential} is true this is
	 * ciphertext; open it with {@link decryptBytes}.
	 */
	get body(): Uint8Array {
		return this.decoded().body;
	}

	/**
	 * The frame carries a non-repudiation signature.
	 */
	get signed(): boolean {
		return this.decoded().signature !== undefined;
	}

	/**
	 * The metadata commits to the body (message integrity).
	 */
	get messageIntegrity(): boolean {
		return this.decoded().messageIntegrity !== undefined;
	}

	/**
	 * The envelope is witnessed (frame integrity).
	 */
	get frameIntegrity(): boolean {
		return this.decoded().frameIntegrity !== undefined;
	}

	/**
	 * The body is encrypted.
	 */
	get confidential(): boolean {
		return this.decoded().confidentiality !== undefined;
	}

	/**
	 * The carried message-commitment digest, when committed.
	 */
	get messageIntegrityInfo(): DigestInfo | undefined {
		return this.decoded().messageIntegrity;
	}

	/**
	 * The carried witness digest, when witnessed.
	 */
	get frameIntegrityInfo(): DigestInfo | undefined {
		return this.decoded().frameIntegrity;
	}

	/**
	 * The carried confidentiality info, when encrypted.
	 */
	get confidentialityInfo(): ConfidentialityInfo | undefined {
		return this.decoded().confidentiality;
	}

	/**
	 * The carried signature info, when signed.
	 */
	get signatureInfo(): SignatureInfo | undefined {
		return this.decoded().signature;
	}

	/**
	 * Message priority, when present (V2+).
	 */
	get priority(): MessagePriority | undefined {
		return this.decoded().priority;
	}

	/**
	 * Time-to-live in seconds, when present (V2+).
	 */
	get lifetime(): bigint | undefined {
		return this.decoded().lifetime;
	}

	/**
	 * Parent-frame link by content digest, when present (V2+).
	 */
	get previousFrame(): PreviousFrame | undefined {
		return this.decoded().previousFrame;
	}

	/**
	 * N×N control matrix, when present (V3+).
	 */
	get matrix(): FrameMatrix | undefined {
		return this.decoded().matrix;
	}

	/**
	 * The to-be-signed bytes (everything but the signature field),
	 * mirroring Rust `Frame::to_tbs`. Verify {@link signatureInfo} over
	 * these bytes with any signature library.
	 */
	tbs(): Uint8Array {
		return tbsBytes(this.der);
	}

	/**
	 * The frame-integrity (witness) preimage: the envelope bytes the
	 * carried witness digest is computed over.
	 */
	witnessInput(): Uint8Array {
		return wasmWitnessInput(this.der);
	}

	/**
	 * The message-commitment preimage under `salt` (the salt passed to
	 * `withMessageHasher`; may be empty), computed over the carried body.
	 */
	commitmentInput(salt: Uint8Array): Uint8Array {
		return commitmentPreimage(salt, bodyPreimage(this.body));
	}

	/**
	 * Verify the frame's non-repudiation signature under the tightbeam
	 * profile scheme (secp256k1 ECDSA over SHA3-256), mirroring Rust
	 * `Frame::verify`. Frames signed under other schemes verify from
	 * {@link tbs} and {@link signatureInfo} with your own library.
	 *
	 * @throws when the frame is unsigned, the algorithm differs, or the
	 * signature does not verify.
	 */
	verify(verifyingKey: Secp256k1VerifyingKey): void {
		wasmVerifySignature(this.der, verifyingKey.toSec1Bytes());
	}

	/**
	 * Check the carried witness digest by recomputing it with `hasher`
	 * (profile SHA3-256 by default), mirroring Rust
	 * `Frame::frame_integrity_verdict::<D>`.
	 */
	frameIntegrityVerdict(
		hasher: Hasher = new Sha3_256(),
	): Promise<IntegrityVerdict> {
		return verdictOf(this.decoded().frameIntegrity, hasher, () =>
			this.witnessInput(),
		);
	}

	/**
	 * Check the carried message commitment against the disclosed `salt` by
	 * recomputing it with `hasher` (profile SHA3-256 by default), mirroring
	 * Rust `Frame::message_commitment_verdict::<D>`. The commitment is over
	 * the plaintext body, so decrypt a confidential frame first and check
	 * the commitment on the plaintext side.
	 */
	messageCommitmentVerdict(
		salt: Uint8Array,
		hasher: Hasher = new Sha3_256(),
	): Promise<IntegrityVerdict> {
		return verdictOf(this.decoded().messageIntegrity, hasher, () =>
			this.commitmentInput(salt),
		);
	}

	/**
	 * Decrypt the encrypted body with any {@link BodyDecryptor} and resolve
	 * with the plaintext payload, mirroring Rust `Frame::decrypt_bytes`.
	 * The profile decryptors are `Aes256Gcm` and `EciesDecryptor`.
	 *
	 * @throws ValidationError when the frame is not encrypted.
	 * @throws when the decryptor rejects the sealed body (wrong key or
	 * algorithm).
	 */
	async decryptBytes(decryptor: BodyDecryptor): Promise<Uint8Array> {
		const confidentiality = this.decoded().confidentiality;
		if (confidentiality === undefined) {
			throw new ValidationError("FRAME_NOT_CONFIDENTIAL", [
				{
					path: "frame",
					message: "The frame body is not encrypted",
				},
			]);
		}

		const plaintextDer = await decryptor.decrypt({
			algorithmOid: confidentiality.algorithmOid,
			parametersDer: confidentiality.parametersDer,
			ciphertext: this.decoded().body,
		});

		return decodeBody(plaintextDer);
	}
}
