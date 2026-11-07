/**
 * A decoded tightbeam frame with its metadata, carried security infos, and
 * verification methods.
 *
 * The verdict methods recompute digests with any {@link Hasher}, and the
 * preimage accessors ({@link Frame.signaturePrehash},
 * {@link Frame.witnessInput}, {@link Frame.commitmentInput}) expose the exact
 * bytes to check signatures and digests with any external library.
 */

import type {
	CommitmentSalt,
	CompactnessInfo as CarriedCompactness,
	ConfidentialityInfo as CarriedConfidentiality,
	DigestInfo,
	DigestVerdict,
	FrameAssembly,
	FrameMatrix,
	InspectedFrame,
	MessagePriority,
	SignatureInfo as CarriedSignature,
	Version,
} from "#wasm";

import type { BodyInflator, ZstdView } from "./compress.js";
import type { BodyDecryptor, FrameVerifier, Hasher } from "./crypto.js";
import type { Engine, EngineModule, EngineParts } from "./engine.js";
import type { MessageCodec } from "./message.js";
import { ValidationError } from "./builder/errors.js";
import { CEILING } from "./compress.js";
import { DigestInfoView, OidView } from "./views.js";

/**
 * An integrity-check outcome: the verdict of the engine on a carried digest,
 * or `"absent"` for a frame that carries nothing to check. Only `"verified"`
 * means the check passed.
 */
export type IntegrityVerdict = DigestVerdict | "absent";

/**
 * A link to a parent frame by the digest of its content (V2+).
 */
export type PreviousFrame = DigestInfoView;

/**
 * The compactness info carried by a compressed frame: how the body was
 * compressed. The frame owns each `Oid` and lends it as a view.
 */
export interface CompactnessInfo {
	/**
	 * The body-compression algorithm.
	 */
	readonly algorithmOid: OidView;
	/**
	 * The DER-encoded algorithm parameters, when the scheme has any.
	 */
	readonly parametersDer?: Uint8Array;
	/**
	 * The content type of the uncompressed body.
	 */
	readonly contentOid: OidView;
}

/**
 * The confidentiality info carried by an encrypted frame: the CMS envelope
 * that seals the body ciphertext. The frame owns the `Oid` and lends it as a
 * view.
 */
export interface ConfidentialityInfo {
	/**
	 * The content-encryption algorithm.
	 */
	readonly algorithmOid: OidView;
	/**
	 * The DER `AuthEnvelopedData`, its content detached into the frame body.
	 */
	readonly envelopeDer: Uint8Array;
}

/**
 * The non-repudiation signature carried by a signed frame. The frame owns
 * each `Oid` and lends it as a view.
 */
export interface SignatureInfo {
	/**
	 * The signature algorithm.
	 */
	readonly algorithmOid: OidView;
	/**
	 * The digest the signature is computed over.
	 */
	readonly digestAlgorithmOid: OidView;
	/**
	 * The DER signature octets.
	 */
	readonly signature: Uint8Array;
}

export type { FrameMatrix } from "#wasm";

/**
 * The decoded fields of one frame, read once from the wasm inspect payload.
 */
class FrameFields {
	readonly version: Version;
	readonly id: Uint8Array;
	readonly order: bigint;
	readonly bodyDer: Uint8Array;
	readonly priority: MessagePriority | undefined;
	readonly lifetime: bigint | undefined;
	readonly previousFrame: PreviousFrame | undefined;
	readonly matrix: FrameMatrix | undefined;
	readonly messageIntegrity: DigestInfoView | undefined;
	readonly frameIntegrity: DigestInfoView | undefined;
	readonly compactness: CompactnessInfo | undefined;
	readonly confidentiality: ConfidentialityInfo | undefined;
	readonly signature: SignatureInfo | undefined;

	/**
	 * Read the fields of `inspected`. Each security field arrives whole or
	 * not at all. The fields own each handle the decode made, and lend each
	 * one as a view.
	 */
	private constructor(inspected: InspectedFrame) {
		this.version = inspected.version;
		this.id = inspected.id;
		this.order = inspected.order;
		this.bodyDer = inspected.bodyDer;
		this.priority = inspected.priority;
		this.lifetime = inspected.lifetime;
		this.previousFrame = FrameFields.digestOf(inspected.previousFrame);
		this.matrix = inspected.matrix;
		const messageIntegrity = inspected.messageIntegrity;
		this.messageIntegrity = FrameFields.digestOf(messageIntegrity);
		this.frameIntegrity = FrameFields.digestOf(inspected.frameIntegrity);
		this.compactness = FrameFields.compactnessOf(inspected.compactness);
		const confidentiality = inspected.confidentiality;
		this.confidentiality = FrameFields.confidentialityOf(confidentiality);
		this.signature = FrameFields.signatureOf(inspected.signature);
	}

	/**
	 * The view of a carried digest, or `undefined` for a field the frame
	 * omits.
	 */
	private static digestOf(
		carried: DigestInfo | undefined,
	): DigestInfoView | undefined {
		if (carried === undefined) {
			return undefined;
		}

		const algorithmOid = carried.algorithmOid;
		const view = DigestInfoView.over(carried, algorithmOid);
		return view;
	}

	/**
	 * The compactness info with each `Oid` lent as a view.
	 */
	private static compactnessOf(
		carried: CarriedCompactness | undefined,
	): CompactnessInfo | undefined {
		if (carried === undefined) {
			return undefined;
		}

		const algorithmOid = OidView.over(carried.algorithmOid);
		const contentOid = OidView.over(carried.contentOid);
		const compactness = { ...carried, algorithmOid, contentOid };
		return compactness;
	}

	/**
	 * The confidentiality info with its `Oid` lent as a view.
	 */
	private static confidentialityOf(
		carried: CarriedConfidentiality | undefined,
	): ConfidentialityInfo | undefined {
		if (carried === undefined) {
			return undefined;
		}

		const algorithmOid = OidView.over(carried.algorithmOid);
		const confidentiality = { ...carried, algorithmOid };
		return confidentiality;
	}

	/**
	 * The signature info with each `Oid` lent as a view.
	 */
	private static signatureOf(
		carried: CarriedSignature | undefined,
	): SignatureInfo | undefined {
		if (carried === undefined) {
			return undefined;
		}

		const algorithmOid = OidView.over(carried.algorithmOid);
		const digestAlgorithmOid = OidView.over(carried.digestAlgorithmOid);

		const signature = { ...carried, algorithmOid, digestAlgorithmOid };
		return signature;
	}

	/**
	 * Decode the frame `der` encodes through one wasm assembly of
	 * `assemblies`, and free the assembly once its summary is read.
	 */
	static decode(
		assemblies: EngineModule["FrameAssembly"],
		der: Uint8Array,
	): FrameFields {
		const assembly = assemblies.decode(der);
		try {
			const inspected = assembly.summary();
			const fields = new FrameFields(inspected);
			return fields;
		} finally {
			assembly.free();
		}
	}
}

/**
 * What the engine answered for one preimage: its octets, or the refusal it
 * raised in their place.
 */
type PreimageAnswer =
	{ readonly octets: Uint8Array } | { readonly refusal: unknown };

/**
 * One preimage of a frame, as the engine answered it once.
 */
class Preimage {
	readonly #answer: PreimageAnswer;

	private constructor(answer: PreimageAnswer) {
		this.#answer = answer;
	}

	/**
	 * The answer of `reader`: the octets it returns, or the refusal it throws,
	 * which the preimage holds and raises at each read.
	 */
	static read(reader: () => Uint8Array): Preimage {
		try {
			const octets = reader();
			const read = new Preimage({ octets });
			return read;
		} catch (refusal) {
			const refused = new Preimage({ refusal });
			return refused;
		}
	}

	/**
	 * A copy of the octets, so a write to it leaves the preimage unchanged.
	 *
	 * @throws The refusal of the engine, when it refused the preimage.
	 */
	copy(): Uint8Array {
		const answer = this.#answer;
		if ("refusal" in answer) {
			throw answer.refusal;
		}

		const copy = new Uint8Array(answer.octets);
		return copy;
	}
}

/**
 * The preimages that the verification of one frame reads, all read from one
 * wasm decode of the frame.
 *
 * Each preimage holds the answer of the engine on its own, so a frame whose
 * signature prehash the engine refuses still reads its other preimages.
 */
class FramePreimages {
	/**
	 * The to-be-signed octets.
	 */
	readonly tbs: Preimage;

	/**
	 * The frame-integrity (witness) preimage.
	 */
	readonly witness: Preimage;

	/**
	 * The digest the signature verifies over, which the engine refuses with
	 * `MissingSignature` for an unsigned frame.
	 */
	readonly prehash: Preimage;

	private constructor(assembly: FrameAssembly) {
		this.tbs = Preimage.read(() => assembly.tbs());
		this.witness = Preimage.read(() => assembly.witnessPreimage());
		this.prehash = Preimage.read(() => assembly.signaturePrehash());
	}

	/**
	 * Decode the frame `der` encodes through one wasm assembly of
	 * `assemblies`, and free the assembly once its preimages are read.
	 */
	static decode(
		assemblies: EngineModule["FrameAssembly"],
		der: Uint8Array,
	): FramePreimages {
		const assembly = assemblies.decode(der);
		try {
			const preimages = new FramePreimages(assembly);
			return preimages;
		} finally {
			assembly.free();
		}
	}
}

/**
 * The capabilities {@link Frame.open} reverses a body with, each in a field
 * of its own name.
 */
export interface OpenOptions {
	/**
	 * Opens a sealed body.
	 */
	readonly opener?: BodyDecryptor;
	/**
	 * Inflates a compressed body.
	 */
	readonly inflator?: BodyInflator;
}

/**
 * An inflator paired with the compactness info it admitted.
 */
interface Inflation {
	readonly inflator: BodyInflator;
	readonly compactness: CompactnessInfo;
}

/**
 * A tightbeam frame.
 *
 * - `Engine.frame` parses received bytes, and the fluent builder's `build()`
 *   makes one. Either way the bytes parse once, at construction.
 * - Every getter reads decoded state, and the frame holds no wasm object
 *   between calls.
 */
export class Frame {
	/**
	 * The preimages, once the first read of one decoded them.
	 */
	#preimages: FramePreimages | undefined;

	readonly #parts: EngineParts;

	private constructor(
		parts: EngineParts,
		private readonly der: Uint8Array,
		private readonly fields: FrameFields,
	) {
		this.#parts = parts;
	}

	/**
	 * Parse a frame DER through the engine `parts`. The frame keeps its own
	 * copy, so a later write to `der` leaves the frame as it parsed.
	 *
	 * @throws TightbeamTransportError with the code of the engine's refusal,
	 * such as `SerializationError`, when the bytes are not a well-formed
	 * frame.
	 */
	static decode(parts: EngineParts, der: Uint8Array): Frame {
		// The constructor copies a Node `Buffer` too, whose `slice` is a view.
		const owned = new Uint8Array(der);

		const fields = FrameFields.decode(parts.glue.FrameAssembly, owned);
		const frame = new Frame(parts, owned, fields);
		return frame;
	}

	/**
	 * Parse the DER of a response frame through `engine`, or answer
	 * `undefined` when the peer returned no response frame.
	 *
	 * @throws ValidationError as {@link decode} does.
	 */
	static response(
		engine: Engine,
		der: Uint8Array | undefined,
	): Frame | undefined {
		if (der === undefined) {
			return undefined;
		}

		const frame = engine.frame(der);
		return frame;
	}

	/**
	 * A copy of the frame DER, so a write to it leaves this frame unchanged.
	 */
	toDer(): Uint8Array {
		const der = new Uint8Array(this.der);
		return der;
	}

	/**
	 * Protocol version.
	 */
	get version(): Version {
		const version = this.fields.version;
		return version;
	}

	/**
	 * A copy of the opaque message identifier, so a write to it leaves this
	 * frame unchanged.
	 */
	get id(): Uint8Array {
		const id = new Uint8Array(this.fields.id);
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
		const order = this.fields.order;
		return order;
	}

	/**
	 * A copy of the raw frame body DER, so a write to it leaves what
	 * {@link open} and {@link message} decode unchanged.
	 *
	 * When {@link confidential} is true, the octets are ciphertext. Open
	 * them with {@link open}. Decode a cleartext body into a typed message
	 * with {@link message}.
	 */
	get bodyDer(): Uint8Array {
		const bodyDer = new Uint8Array(this.fields.bodyDer);
		return bodyDer;
	}

	/**
	 * The frame carries a non-repudiation signature.
	 */
	get signed(): boolean {
		const signed = this.fields.signature !== undefined;
		return signed;
	}

	/**
	 * The metadata commits to the body (message integrity).
	 */
	get messageIntegrity(): boolean {
		const messageIntegrity = this.fields.messageIntegrity !== undefined;
		return messageIntegrity;
	}

	/**
	 * The envelope is witnessed (frame integrity).
	 */
	get frameIntegrity(): boolean {
		const frameIntegrity = this.fields.frameIntegrity !== undefined;
		return frameIntegrity;
	}

	/**
	 * The body is compressed.
	 */
	get compressed(): boolean {
		const compressed = this.fields.compactness !== undefined;
		return compressed;
	}

	/**
	 * The body is encrypted.
	 */
	get confidential(): boolean {
		const confidential = this.fields.confidentiality !== undefined;
		return confidential;
	}

	/**
	 * The carried message-commitment digest, when committed.
	 */
	get messageIntegrityInfo(): DigestInfoView | undefined {
		const messageIntegrityInfo = this.fields.messageIntegrity;
		return messageIntegrityInfo;
	}

	/**
	 * The carried witness digest, when witnessed.
	 */
	get frameIntegrityInfo(): DigestInfoView | undefined {
		const frameIntegrityInfo = this.fields.frameIntegrity;
		return frameIntegrityInfo;
	}

	/**
	 * A copy of the carried compactness info, when compressed, so a write to
	 * it leaves what {@link open} inflates with unchanged.
	 */
	get compactnessInfo(): CompactnessInfo | undefined {
		const carried = this.fields.compactness;
		if (carried === undefined) {
			return undefined;
		}

		const parameters = carried.parametersDer;
		if (parameters === undefined) {
			const compactnessInfo = { ...carried };
			return compactnessInfo;
		}

		const parametersDer = new Uint8Array(parameters);
		const compactnessInfo = { ...carried, parametersDer };
		return compactnessInfo;
	}

	/**
	 * A copy of the carried confidentiality info, when encrypted, so a write
	 * to it leaves what {@link open} decrypts with unchanged.
	 */
	get confidentialityInfo(): ConfidentialityInfo | undefined {
		const carried = this.fields.confidentiality;
		if (carried === undefined) {
			return undefined;
		}

		const envelopeDer = new Uint8Array(carried.envelopeDer);
		const confidentialityInfo = { ...carried, envelopeDer };
		return confidentialityInfo;
	}

	/**
	 * A copy of the carried signature info, when signed, so a write to it
	 * leaves this frame unchanged.
	 */
	get signatureInfo(): SignatureInfo | undefined {
		const carried = this.fields.signature;
		if (carried === undefined) {
			return undefined;
		}

		const signature = new Uint8Array(carried.signature);
		const signatureInfo = { ...carried, signature };
		return signatureInfo;
	}

	/**
	 * Message priority, when present (V2+).
	 */
	get priority(): MessagePriority | undefined {
		const priority = this.fields.priority;
		return priority;
	}

	/**
	 * Time-to-live in seconds, when present (V2+).
	 */
	get lifetime(): bigint | undefined {
		const lifetime = this.fields.lifetime;
		return lifetime;
	}

	/**
	 * Parent-frame link by content digest, when present (V2+).
	 */
	get previousFrame(): PreviousFrame | undefined {
		const previousFrame = this.fields.previousFrame;
		return previousFrame;
	}

	/**
	 * A copy of the N×N control matrix, when present (V3+), so a write to it
	 * leaves this frame unchanged.
	 */
	get matrix(): FrameMatrix | undefined {
		const carried = this.fields.matrix;
		if (carried === undefined) {
			return undefined;
		}

		const data = new Uint8Array(carried.data);
		const matrix = { ...carried, data };
		return matrix;
	}

	/**
	 * The to-be-signed bytes (everything but the signature field). The CMS
	 * signed attributes bind their digest, and {@link signatureInfo} verifies
	 * over {@link signaturePrehash}.
	 */
	tbs(): Uint8Array {
		const tbs = this.preimages.tbs.copy();
		return tbs;
	}

	/**
	 * The digest this frame's signature verifies over: the digest of its CMS
	 * signed attributes, which bind {@link tbs} (RFC 5652 § 5.4).
	 *
	 * @throws an error whose `code` is `MissingSignature` when the frame is
	 * unsigned.
	 */
	signaturePrehash(): Uint8Array {
		const prehash = this.preimages.prehash.copy();
		return prehash;
	}

	/**
	 * The frame-integrity (witness) preimage: the envelope bytes the
	 * carried witness digest is computed over.
	 */
	witnessInput(): Uint8Array {
		const witness = this.preimages.witness.copy();
		return witness;
	}

	/**
	 * The preimages of this frame, decoded once, on the first read of any:
	 * the lazy cell holds the first decode, so no read decodes again.
	 */
	private get preimages(): FramePreimages {
		const assemblies = this.#parts.glue.FrameAssembly;

		this.#preimages ??= FramePreimages.decode(assemblies, this.der);
		return this.#preimages;
	}

	/**
	 * The message-commitment preimage under `salt`, computed over the
	 * carried body DER.
	 *
	 * Pass a salt that parses the octets given to `withCommitment`.
	 *
	 * @throws ValidationError `FRAME_CONFIDENTIAL` or `FRAME_COMPRESSED` when
	 * the frame is sealed or compressed, so its body still needs an open.
	 * @throws an error whose `code` is `SerializationError` when the plaintext
	 * body is not one DER value.
	 */
	commitmentInput(salt: CommitmentSalt): Uint8Array {
		const bodyDer = this.plainBodyDer();
		const commitmentInput = salt.preimage(bodyDer);
		return commitmentInput;
	}

	/**
	 * Verify the frame's non-repudiation signature through `verifier`.
	 * Profile secp256k1 uses {@link Secp256k1VerifyingKey}; other schemes
	 * supply their own {@link FrameVerifier} (or use
	 * {@link signaturePrehash} / {@link signatureInfo} directly).
	 *
	 * @throws when the frame is unsigned, the algorithm differs, or the
	 * signature does not verify.
	 */
	verify(verifier: FrameVerifier): void {
		verifier.verifyFrame(this);
	}

	/**
	 * Check the carried witness digest by recomputing it with `hasher`
	 * (profile SHA3-256 by default).
	 */
	async frameIntegrityVerdict(
		hasher: Hasher = this.#parts.sha3_256,
	): Promise<IntegrityVerdict> {
		const carried = this.fields.frameIntegrity;
		if (carried === undefined) {
			return "absent";
		}

		const preimage = this.witnessInput();
		const verdict = await Frame.verdictOf(carried, hasher, preimage);
		return verdict;
	}

	/**
	 * Check the carried message commitment against the disclosed `salt` by
	 * recomputing it with `hasher` (profile SHA3-256 by default). The
	 * commitment is over the plaintext, uncompressed body: open a sealed or
	 * compressed frame first and check the commitment on the recovered body.
	 *
	 * @throws ValidationError `FRAME_CONFIDENTIAL` or `FRAME_COMPRESSED` when
	 * the frame is sealed or compressed, so its body still needs an open.
	 * @throws an error whose `code` is `SerializationError` when the plaintext
	 * body is not one DER value.
	 */
	async messageCommitmentVerdict(
		salt: CommitmentSalt,
		hasher: Hasher = this.#parts.sha3_256,
	): Promise<IntegrityVerdict> {
		const carried = this.fields.messageIntegrity;
		if (carried === undefined) {
			return "absent";
		}

		const preimage = this.commitmentInput(salt);
		const verdict = await Frame.verdictOf(carried, hasher, preimage);
		return verdict;
	}

	/**
	 * The verdict of the engine on `carried` against `preimage` digested by
	 * `hasher`.
	 */
	private static async verdictOf(
		carried: DigestInfoView,
		hasher: Hasher,
		preimage: Uint8Array,
	): Promise<DigestVerdict> {
		const recomputed = await hasher.digest(preimage);
		const verdict = carried.verdict(hasher.algorithmOid, recomputed);
		return verdict;
	}

	/**
	 * Decode the cleartext body into a typed message under `codec` - the
	 * profile `Opaque` codec for raw bytes, or the implementor's schema.
	 * The codec runtime-validates the bytes and throws on mismatch.
	 *
	 * @throws ValidationError when the frame is encrypted or compressed
	 * (use {@link open}).
	 */
	message<T>(codec: MessageCodec<T>): T {
		const bodyDer = this.plainBodyDer();
		const message = codec.decode(bodyDer);
		return message;
	}

	/**
	 * The carried body, once the frame's own confidentiality and compactness
	 * show it is plaintext.
	 *
	 * @throws ValidationError `FRAME_CONFIDENTIAL` when the frame is sealed.
	 * @throws ValidationError `FRAME_COMPRESSED` when the frame is compressed.
	 */
	private plainBodyDer(): Uint8Array {
		if (this.confidential) {
			throw new ValidationError("FRAME_CONFIDENTIAL", [
				{
					path: "frame",
					message: "The frame body is encrypted. Decode it with open",
				},
			]);
		}
		if (this.compressed) {
			throw new ValidationError("FRAME_COMPRESSED", [
				{
					path: "frame",
					message:
						"The frame body is compressed. Decode it with open",
				},
			]);
		}

		return this.bodyDer;
	}

	/**
	 * Reverse the layers this frame carries and decode the body under
	 * `codec`: open a sealed body with `opener`, inflate a compressed one
	 * with `inflator`, and decode the result.
	 *
	 * - The inflator admits the compactness info, its algorithm and its
	 *   parameters, before the opener decrypts, so a body no inflator reverses
	 *   costs no decryption.
	 * - A capability the frame does not need goes unused, so an uncompressed
	 *   cleartext frame opens under any options.
	 *
	 * @throws ValidationError with one of these codes:
	 *
	 * - `MISSING_OPENER`: the frame is sealed and no `opener` is given.
	 * - `MISSING_INFLATOR`: the frame is compressed and no `inflator` is given.
	 * - `COMPACTNESS_REFUSED`: the inflator does not admit the compactness info.
	 *
	 * @throws when the opener rejects the sealed body, the inflator rejects
	 * the plaintext, or the codec rejects the decoded bytes.
	 */
	async open<T>(
		codec: MessageCodec<T>,
		options: OpenOptions = {},
	): Promise<T> {
		const inflation = this.admittedInflation(options.inflator);
		const plaintext = await this.decrypted(options.opener);
		if (inflation === undefined) {
			const message = codec.decode(plaintext);
			return message;
		}

		const bodyDer = await inflation.inflator.decompress(plaintext);
		const message = codec.decode(bodyDer);
		return message;
	}

	/**
	 * Inflate the cleartext-but-compressed body with the engine `zstd`, on the
	 * inflate path a native peer takes, and decode the result into a typed
	 * message under `codec`. An uncompressed cleartext body decodes as it is.
	 *
	 * @throws an error whose `code` is `CompressionError` when `zstd` refuses
	 * the body, `UnexpectedAlgorithm` or `InvalidMetadata` when the
	 * compactness info names another algorithm or parameters `zstd` refuses,
	 * and `Router` when the frame is sealed (use {@link open} with an opener
	 * instead).
	 * @throws when the codec rejects the decoded bytes.
	 */
	async inflateMessage<T>(
		zstd: ZstdView,
		codec: MessageCodec<T>,
	): Promise<T> {
		const bodyDer = this.#inflated(zstd);
		const message = codec.decode(bodyDer);
		return message;
	}

	/**
	 * The body DER that the engine inflates within the ceiling of `zstd`,
	 * through one assembly that the read frees.
	 */
	#inflated(zstd: ZstdView): Uint8Array {
		const assemblies = this.#parts.glue.FrameAssembly;
		const assembly = assemblies.decode(this.der);
		try {
			const bodyDer = assembly.inflate(zstd[CEILING]);
			return bodyDer;
		} finally {
			assembly.free();
		}
	}

	/**
	 * Decrypt the encrypted body with any {@link BodyDecryptor} and decode
	 * the plaintext into a typed message under `codec`.
	 *
	 * The profile decryptors are `Aes256Gcm` and `HpkeDecryptor`. The
	 * profile codec for raw bytes is `Opaque`. A compressed-then-sealed
	 * body also needs `inflator` to decompress the decrypted bytes.
	 *
	 * @throws ValidationError when the frame is not encrypted.
	 * @throws as {@link open} does.
	 */
	async decryptMessage<T>(
		decryptor: BodyDecryptor,
		codec: MessageCodec<T>,
		inflator?: BodyInflator,
	): Promise<T> {
		if (!this.confidential) {
			throw new ValidationError("FRAME_NOT_CONFIDENTIAL", [
				{
					path: "frame",
					message: "The frame body is not encrypted",
				},
			]);
		}

		const message = await this.open(codec, { opener: decryptor, inflator });
		return message;
	}

	/**
	 * The inflator for a compressed body, once it admits the carried
	 * compactness info, or `undefined` for an uncompressed body.
	 */
	private admittedInflation(
		inflator: BodyInflator | undefined,
	): Inflation | undefined {
		const compactness = this.compactnessInfo;
		if (compactness === undefined) {
			return undefined;
		}
		if (inflator === undefined) {
			throw new ValidationError("MISSING_INFLATOR", [
				{
					path: "frame",
					message:
						"The frame body is compressed. Open it with an inflator",
				},
			]);
		}

		const algorithm = compactness.algorithmOid;
		const reverses = algorithm.equals(inflator.algorithmOid);
		const parameters = compactness.parametersDer;
		if (!reverses || !inflator.admitsParameters(parameters)) {
			throw new ValidationError("COMPACTNESS_REFUSED", [
				{
					path: "compactness",
					message: `The inflator does not reverse a body compressed with ${compactness.algorithmOid}`,
				},
			]);
		}

		const inflation = { inflator, compactness };
		return inflation;
	}

	/**
	 * The body with any seal removed: a copy of the carried body when
	 * cleartext, or the plaintext `opener` recovers from copies of the
	 * sealed parts.
	 */
	private async decrypted(
		opener: BodyDecryptor | undefined,
	): Promise<Uint8Array> {
		const confidentiality = this.confidentialityInfo;
		const bodyDer = this.bodyDer;
		if (confidentiality === undefined) {
			return bodyDer;
		}
		if (opener === undefined) {
			throw new ValidationError("MISSING_OPENER", [
				{
					path: "frame",
					message:
						"The frame body is encrypted. Open it with an opener",
				},
			]);
		}

		const envelopeDer = confidentiality.envelopeDer;
		const sealed = { envelopeDer, ciphertext: bodyDer };
		const plaintext = await opener.decrypt(sealed);
		return plaintext;
	}
}
