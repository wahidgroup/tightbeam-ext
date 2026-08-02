/**
 * A decoded tightbeam frame with its metadata, carried security infos, and
 * verification methods.
 *
 * Verification is algorithm-agile: the verdict methods recompute digests
 * with any {@link Hasher}, and the preimage accessors ({@link Frame.tbs},
 * {@link Frame.witnessInput}, {@link Frame.commitmentInput}) expose the
 * exact bytes to check signatures and digests with any external library.
 */

import type { InspectedFrame } from "#wasm";
import {
	commitmentPreimage,
	inspectFrameFields,
	tbsBytes,
	verifySignature as wasmVerifySignature,
	witnessInput as wasmWitnessInput,
} from "#wasm";

import type { MessagePriority } from "./builder/priority.js";
import type { Version } from "./builder/version.js";
import type { BodyInflator } from "./compress.js";
import type { BodyDecryptor, Hasher, Secp256k1VerifyingKey } from "./crypto.js";
import type { MessageCodec } from "./message.js";
import { ValidationError } from "./builder/errors.js";
import { priorityFromOrdinal } from "./builder/priority.js";
import { versionFromOrdinal } from "./builder/version.js";
import { Sha3_256 } from "./crypto.js";
import { InternalError } from "./errors.js";
import { wrapped } from "./message.js";

/**
 * The integrity-check outcomes.
 */
export const INTEGRITY_VERDICTS = [
	"verified",
	"absent",
	"algorithm-mismatch",
	"mismatch",
] as const;

/**
 * An integrity-check outcome. Only `"verified"` means the check passed.
 * The value `"absent"` distinguishes a frame that carries nothing to check.
 */
export type IntegrityVerdict = (typeof INTEGRITY_VERDICTS)[number];

/**
 * A digest carried by a frame: the algorithm that produced it and the raw
 * octets of an ASN.1 `DigestInfo`.
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
 * A link to a parent frame by the digest of its content (V2+).
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
 * The compactness info carried by a compressed frame: how the body was
 * compressed.
 */
export interface CompactnessInfo {
	/**
	 * Dotted OID of the body-compression algorithm.
	 */
	readonly algorithmOid: string;
	/**
	 * The DER-encoded algorithm parameters, when the scheme has any.
	 */
	readonly parametersDer?: Uint8Array;
	/**
	 * Content-type OID of the uncompressed body.
	 */
	readonly contentOid?: string;
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
	readonly bodyDer: Uint8Array;
	readonly priority: MessagePriority | undefined;
	readonly lifetime: bigint | undefined;
	readonly previousFrame: PreviousFrame | undefined;
	readonly matrix: FrameMatrix | undefined;
	readonly messageIntegrity: DigestInfo | undefined;
	readonly frameIntegrity: DigestInfo | undefined;
	readonly compactness: CompactnessInfo | undefined;
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

	const digestInfo = { algorithmOid, digest };
	return digestInfo;
}

/**
 * Build the control matrix from an inspected payload, when present.
 */
function matrixOf(inspected: InspectedFrame): FrameMatrix | undefined {
	const n = inspected.matrixN;
	const data = inspected.matrixData;
	if (n === undefined || data === undefined) {
		return undefined;
	}

	const matrix = { n, data };
	return matrix;
}

/**
 * Build compactness info from an inspected payload, when present.
 */
function compactnessOf(inspected: InspectedFrame): CompactnessInfo | undefined {
	const algorithmOid = inspected.compactnessAlgorithmOid;
	if (algorithmOid === undefined) {
		return undefined;
	}

	const compactness = {
		algorithmOid,
		parametersDer: inspected.compactnessParametersDer,
		contentOid: inspected.compactnessContentOid,
	};
	return compactness;
}

/**
 * Build confidentiality info from an inspected payload, when present.
 */
function confidentialityOf(
	inspected: InspectedFrame,
): ConfidentialityInfo | undefined {
	const algorithmOid = inspected.confidentialityAlgorithmOid;
	if (algorithmOid === undefined) {
		return undefined;
	}

	const confidentiality = {
		algorithmOid,
		parametersDer: inspected.confidentialityParametersDer,
	};
	return confidentiality;
}

/**
 * Build signature info from an inspected payload, when present.
 */
function signatureOf(inspected: InspectedFrame): SignatureInfo | undefined {
	const algorithmOid = inspected.signatureAlgorithmOid;
	const digestAlgorithmOid = inspected.signatureDigestAlgorithmOid;
	const signature = inspected.signature;
	if (
		algorithmOid === undefined ||
		digestAlgorithmOid === undefined ||
		signature === undefined
	) {
		return undefined;
	}

	const signatureInfo = { algorithmOid, digestAlgorithmOid, signature };
	return signatureInfo;
}

/**
 * Map a one-shot wasm inspect payload into plain {@link FrameFields}.
 */
function fieldsOf(inspected: InspectedFrame): FrameFields {
	const version = versionFromOrdinal(inspected.version);
	if (version === undefined) {
		throw new InternalError(
			"UNKNOWN_VERSION",
			`the wasm module returned an unknown version ordinal: ${inspected.version}`,
		);
	}

	let priority: MessagePriority | undefined = undefined;
	const priorityOrdinal = inspected.priority;
	if (priorityOrdinal !== undefined) {
		priority = priorityFromOrdinal(priorityOrdinal);
		if (priority === undefined) {
			throw new InternalError(
				"UNKNOWN_PRIORITY",
				`the wasm module returned an unknown priority ordinal: ${priorityOrdinal}`,
			);
		}
	}

	const fields = {
		version,
		id: inspected.id,
		order: inspected.order,
		bodyDer: inspected.bodyDer,
		priority,
		lifetime: inspected.lifetime,
		previousFrame: digestInfoFrom(
			inspected.previousHashAlgorithmOid,
			inspected.previousHashDigest,
		),
		matrix: matrixOf(inspected),
		messageIntegrity: digestInfoFrom(
			inspected.messageIntegrityAlgorithmOid,
			inspected.messageIntegrityDigest,
		),
		frameIntegrity: digestInfoFrom(
			inspected.frameIntegrityAlgorithmOid,
			inspected.frameIntegrityDigest,
		),
		compactness: compactnessOf(inspected),
		confidentiality: confidentialityOf(inspected),
		signature: signatureOf(inspected),
	};
	return fields;
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

	const equal = difference === 0;
	return equal;
}

/**
 * Check a recomputable digest against a carried one.
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
	const verified = digestsEqual(recomputed, carried.digest);
	if (verified) {
		return "verified";
	}

	return "mismatch";
}

/**
 * A tightbeam frame.
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
	 * Wrap a frame DER. Decoding is lazy: structurally invalid bytes throw on
	 * first metadata access, not here.
	 */
	static fromDer(der: Uint8Array): Frame {
		const frame = new Frame(der);
		return frame;
	}

	/**
	 * The frame DER.
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

		const inspected = inspectFrameFields(this.der);
		this.fields = fieldsOf(inspected);
		return this.fields;
	}

	/**
	 * Protocol version.
	 */
	get version(): Version {
		const version = this.decoded().version;
		return version;
	}

	/**
	 * Opaque message identifier.
	 */
	get id(): Uint8Array {
		const id = this.decoded().id;
		return id;
	}

	/**
	 * Frame order stamp.
	 *
	 * The value is protocol-opaque. Any monotonic scheme works, such as a
	 * Unix timestamp or a dense per-channel counter. When omitted at build
	 * time, the profile defaults to the current Unix time in seconds.
	 */
	get order(): bigint {
		const order = this.decoded().order;
		return order;
	}

	/**
	 * The raw frame body DER.
	 *
	 * When {@link confidential} is true, the octets are ciphertext. Open
	 * them with {@link decryptMessage}. Decode a cleartext body into a
	 * typed message with {@link message}.
	 */
	get bodyDer(): Uint8Array {
		const bodyDer = this.decoded().bodyDer;
		return bodyDer;
	}

	/**
	 * The frame carries a non-repudiation signature.
	 */
	get signed(): boolean {
		const signed = this.decoded().signature !== undefined;
		return signed;
	}

	/**
	 * The metadata commits to the body (message integrity).
	 */
	get messageIntegrity(): boolean {
		const messageIntegrity = this.decoded().messageIntegrity !== undefined;
		return messageIntegrity;
	}

	/**
	 * The envelope is witnessed (frame integrity).
	 */
	get frameIntegrity(): boolean {
		const frameIntegrity = this.decoded().frameIntegrity !== undefined;
		return frameIntegrity;
	}

	/**
	 * The body is compressed.
	 */
	get compressed(): boolean {
		const compressed = this.decoded().compactness !== undefined;
		return compressed;
	}

	/**
	 * The body is encrypted.
	 */
	get confidential(): boolean {
		const confidential = this.decoded().confidentiality !== undefined;
		return confidential;
	}

	/**
	 * The carried message-commitment digest, when committed.
	 */
	get messageIntegrityInfo(): DigestInfo | undefined {
		const messageIntegrityInfo = this.decoded().messageIntegrity;
		return messageIntegrityInfo;
	}

	/**
	 * The carried witness digest, when witnessed.
	 */
	get frameIntegrityInfo(): DigestInfo | undefined {
		const frameIntegrityInfo = this.decoded().frameIntegrity;
		return frameIntegrityInfo;
	}

	/**
	 * The carried compactness info, when compressed.
	 */
	get compactnessInfo(): CompactnessInfo | undefined {
		const compactnessInfo = this.decoded().compactness;
		return compactnessInfo;
	}

	/**
	 * The carried confidentiality info, when encrypted.
	 */
	get confidentialityInfo(): ConfidentialityInfo | undefined {
		const confidentialityInfo = this.decoded().confidentiality;
		return confidentialityInfo;
	}

	/**
	 * The carried signature info, when signed.
	 */
	get signatureInfo(): SignatureInfo | undefined {
		const signatureInfo = this.decoded().signature;
		return signatureInfo;
	}

	/**
	 * Message priority, when present (V2+).
	 */
	get priority(): MessagePriority | undefined {
		const priority = this.decoded().priority;
		return priority;
	}

	/**
	 * Time-to-live in seconds, when present (V2+).
	 */
	get lifetime(): bigint | undefined {
		const lifetime = this.decoded().lifetime;
		return lifetime;
	}

	/**
	 * Parent-frame link by content digest, when present (V2+).
	 */
	get previousFrame(): PreviousFrame | undefined {
		const previousFrame = this.decoded().previousFrame;
		return previousFrame;
	}

	/**
	 * N×N control matrix, when present (V3+).
	 */
	get matrix(): FrameMatrix | undefined {
		const matrix = this.decoded().matrix;
		return matrix;
	}

	/**
	 * The to-be-signed bytes (everything but the signature field). Verify
	 * {@link signatureInfo} over these bytes with any signature library.
	 */
	tbs(): Uint8Array {
		const tbs = tbsBytes(this.der);
		return tbs;
	}

	/**
	 * The frame-integrity (witness) preimage: the envelope bytes the
	 * carried witness digest is computed over.
	 */
	witnessInput(): Uint8Array {
		const witnessInput = wasmWitnessInput(this.der);
		return witnessInput;
	}

	/**
	 * The message-commitment preimage under `salt`, computed over the
	 * carried body DER.
	 *
	 * Pass the same salt given to `withMessageHasher`. An empty salt is valid.
	 */
	commitmentInput(salt: Uint8Array): Uint8Array {
		const commitmentInput = commitmentPreimage(salt, this.bodyDer);
		return commitmentInput;
	}

	/**
	 * Verify the frame's non-repudiation signature under the tightbeam
	 * profile scheme (secp256k1 ECDSA over SHA3-256). Frames signed under
	 * other schemes verify from {@link tbs} and {@link signatureInfo} with
	 * your own library.
	 *
	 * @throws when the frame is unsigned, the algorithm differs, or the
	 * signature does not verify.
	 */
	verify(verifyingKey: Secp256k1VerifyingKey): void {
		wasmVerifySignature(this.der, verifyingKey.toSec1Bytes());
	}

	/**
	 * Check the carried witness digest by recomputing it with `hasher`
	 * (profile SHA3-256 by default).
	 */
	frameIntegrityVerdict(
		hasher: Hasher = new Sha3_256(),
	): Promise<IntegrityVerdict> {
		const verdict = verdictOf(this.decoded().frameIntegrity, hasher, () =>
			this.witnessInput(),
		);
		return verdict;
	}

	/**
	 * Check the carried message commitment against the disclosed `salt` by
	 * recomputing it with `hasher` (profile SHA3-256 by default). The
	 * commitment is over the plaintext, uncompressed body: decrypt and/or
	 * decompress a sealed or compressed frame first and check the
	 * commitment on the recovered body.
	 */
	messageCommitmentVerdict(
		salt: Uint8Array,
		hasher: Hasher = new Sha3_256(),
	): Promise<IntegrityVerdict> {
		const verdict = verdictOf(this.decoded().messageIntegrity, hasher, () =>
			this.commitmentInput(salt),
		);
		return verdict;
	}

	/**
	 * Decode the cleartext body into a typed message under `codec` - the
	 * profile `Opaque` codec for raw bytes, or the implementor's schema.
	 * The codec runtime-validates the bytes and throws on mismatch.
	 *
	 * @throws ValidationError when the frame is encrypted (use
	 * {@link decryptMessage}) or compressed (use {@link inflateMessage}).
	 */
	message<T>(codec: MessageCodec<T>): T {
		if (this.confidential) {
			throw new ValidationError("FRAME_CONFIDENTIAL", [
				{
					path: "frame",
					message:
						"The frame body is encrypted. Decode it with decryptMessage",
				},
			]);
		}
		if (this.compressed) {
			throw new ValidationError("FRAME_COMPRESSED", [
				{
					path: "frame",
					message:
						"The frame body is compressed. Decode it with inflateMessage",
				},
			]);
		}

		const message = codec.decode(this.bodyDer);
		return message;
	}

	/**
	 * Decompress the cleartext-but-compressed body with any
	 * {@link BodyInflator} and decode the result into a typed message
	 * under `codec`.
	 *
	 * @throws ValidationError when the frame is not compressed, or is also
	 * encrypted (use {@link decryptMessage} with the inflator instead).
	 * @throws when the inflator rejects the carried body or the codec
	 * rejects the decompressed bytes.
	 */
	async inflateMessage<T>(
		inflator: BodyInflator,
		codec: MessageCodec<T>,
	): Promise<T> {
		if (this.confidential) {
			throw new ValidationError("FRAME_CONFIDENTIAL", [
				{
					path: "frame",
					message:
						"The frame body is encrypted. Decode it with decryptMessage",
				},
			]);
		}

		const compactness = this.decoded().compactness;
		if (compactness === undefined) {
			throw new ValidationError("FRAME_NOT_COMPRESSED", [
				{
					path: "frame",
					message: "The frame body is not compressed",
				},
			]);
		}

		const bodyDer = await inflator.decompress({
			algorithmOid: compactness.algorithmOid,
			parametersDer: compactness.parametersDer,
			contentOid: compactness.contentOid,
			data: this.bodyDer,
		});

		const message = codec.decode(bodyDer);
		return message;
	}

	/**
	 * Decrypt the encrypted body with any {@link BodyDecryptor} and decode
	 * the plaintext into a typed message under `codec`.
	 *
	 * The profile decryptors are `Aes256Gcm` and `EciesDecryptor`. The
	 * profile codec for raw bytes is `Opaque`. A compressed-then-sealed
	 * body also needs `inflator` to decompress the decrypted bytes.
	 *
	 * @throws ValidationError when the frame is not encrypted, or is
	 * compressed and no `inflator` is given.
	 * @throws when the decryptor rejects the sealed body (wrong key or
	 * algorithm), the inflator rejects the plaintext, or the codec rejects
	 * the decompressed bytes.
	 */
	async decryptMessage<T>(
		decryptor: BodyDecryptor,
		codec: MessageCodec<T>,
		inflator?: BodyInflator,
	): Promise<T> {
		const confidentiality = this.decoded().confidentiality;
		if (confidentiality === undefined) {
			throw new ValidationError("FRAME_NOT_CONFIDENTIAL", [
				{
					path: "frame",
					message: "The frame body is not encrypted",
				},
			]);
		}

		const compactness = this.decoded().compactness;
		if (compactness !== undefined && inflator === undefined) {
			throw new ValidationError("MISSING_INFLATOR", [
				{
					path: "frame",
					message:
						"The frame body is compressed. decryptMessage needs an inflator.",
				},
			]);
		}

		const plaintext = await decryptor.decrypt({
			algorithmOid: confidentiality.algorithmOid,
			parametersDer: confidentiality.parametersDer,
			ciphertext: this.decoded().bodyDer,
		});

		const bodyDer = await inflate(plaintext, compactness, inflator);
		const message = codec.decode(bodyDer);
		return message;
	}
}

/**
 * Frame-in-frame payloads: a codec whose messages are full tightbeam
 * frames, carried untouched inside another frame's body.
 *
 * Made for pub/sub topics: the registry stamps its wrapper (topic id,
 * dense order) while the published inner frame relays byte-for-byte, so
 * publisher-applied security (signature, commitment, encrypted or
 * compressed body) survives the broker end to end and verifies on the
 * subscriber.
 */
export const Framed: MessageCodec<Frame> = wrapped({
	encode(inner: Frame): Uint8Array {
		const der = inner.toDer();
		return der;
	},
	decode(payload: Uint8Array): Frame {
		const frame = Frame.fromDer(payload);
		return frame;
	},
});

/**
 * Decompress decrypted plaintext when the frame carries compactness info.
 * Pass uncompressed plaintext through unchanged. The missing-inflator case
 * is rejected before decryption runs.
 */
async function inflate(
	plaintext: Uint8Array,
	compactness: CompactnessInfo | undefined,
	inflator: BodyInflator | undefined,
): Promise<Uint8Array> {
	if (compactness === undefined || inflator === undefined) {
		return plaintext;
	}

	const bodyDer = await inflator.decompress({
		algorithmOid: compactness.algorithmOid,
		parametersDer: compactness.parametersDer,
		contentOid: compactness.contentOid,
		data: plaintext,
	});
	return bodyDer;
}
