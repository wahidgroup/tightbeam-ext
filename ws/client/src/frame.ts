/**
 * A decoded tightbeam frame with its metadata, carried security infos, and
 * verification methods, as the frame section of `docs/ws-client.md` describes.
 */

import type {
	CommitmentSalt,
	CompactnessInfo as CarriedCompactness,
	ConfidentialityInfo as CarriedConfidentiality,
	DigestInfo,
	FrameAssembly,
	FrameBody,
	FrameMatrix,
	InspectedFrame,
	IntegrityVerdict,
	MessagePriority,
	SignatureInfo as CarriedSignature,
	Version,
} from "#wasm";

import type { BodyInflator, Inflation } from "./compress.js";
import type { BodyDecryptor, FrameVerifier, Hasher } from "./crypto.js";
import type { EngineParts } from "./engine.js";
import type { MessageCodec } from "./message.js";
import { HeldInflator } from "./compress.js";
import { ClientTransportError } from "./errors.js";
import { DigestInfoView, OidView } from "./views.js";

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
 * that seals the body ciphertext. The frame owns each `Oid` and lends it as a
 * view.
 */
export interface ConfidentialityInfo {
	/**
	 * The content-encryption algorithm.
	 */
	readonly algorithmOid: OidView;
	/**
	 * The content type that the envelope authenticates for the sealed body.
	 */
	readonly contentOid: OidView;
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
 * The body of a frame by the layer a reader reverses first, with each `Oid`
 * of its infos lent as a view.
 */
type BodyLayers =
	| { readonly layer: "plain"; readonly der: Uint8Array }
	| {
			readonly layer: "compressed";
			readonly data: Uint8Array;
			readonly compactness: CompactnessInfo;
	  }
	| {
			readonly layer: "sealed";
			readonly ciphertext: Uint8Array;
			readonly confidentiality: ConfidentialityInfo;
			readonly compactness: CompactnessInfo | undefined;
	  };

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
 * The body a frame carries, as the engine decided its layer once at the
 * decode. It owns how a read reverses the layer.
 */
class CarriedBody {
	readonly #body: BodyLayers;

	private constructor(body: BodyLayers) {
		this.#body = body;
	}

	/**
	 * The body that the engine decoded as `carried`.
	 */
	static of(carried: FrameBody): CarriedBody {
		switch (carried.layer) {
			case "plain":
				return new CarriedBody(carried);
			case "compressed": {
				const compactness = CarriedBody.compactnessOf(carried.compactness);
				return new CarriedBody({ ...carried, compactness });
			}
			case "sealed": {
				const confidentiality = CarriedBody.confidentialityOf(carried.confidentiality);
				let compactness: CompactnessInfo | undefined;
				if (carried.compactness !== undefined) {
					compactness = CarriedBody.compactnessOf(carried.compactness);
				}

				return new CarriedBody({
					...carried,
					confidentiality,
					compactness,
				});
			}
			default: {
				const unknown: never = carried;
				return unknown;
			}
		}
	}

	/**
	 * The compactness info with each `Oid` lent as a view.
	 */
	private static compactnessOf(carried: CarriedCompactness): CompactnessInfo {
		const algorithmOid = OidView.over(carried.algorithmOid);
		const contentOid = OidView.over(carried.contentOid);
		const compactness = { ...carried, algorithmOid, contentOid };
		return compactness;
	}

	/**
	 * The confidentiality info with each `Oid` lent as a view.
	 */
	private static confidentialityOf(carried: CarriedConfidentiality): ConfidentialityInfo {
		const algorithmOid = OidView.over(carried.algorithmOid);
		const contentOid = OidView.over(carried.contentOid);
		const confidentiality = { ...carried, algorithmOid, contentOid };
		return confidentiality;
	}

	/**
	 * The octets the frame carries as its body: the body DER, the compressed
	 * octets, or the ciphertext.
	 */
	get octets(): Uint8Array {
		const body = this.#body;
		switch (body.layer) {
			case "plain":
				return body.der;
			case "compressed":
				return body.data;
			case "sealed":
				return body.ciphertext;
			default: {
				const unknown: never = body;
				return unknown;
			}
		}
	}

	/**
	 * How the body compressed, when it did, under the seal or not.
	 */
	get compactness(): CompactnessInfo | undefined {
		const body = this.#body;
		if (body.layer === "plain") {
			return undefined;
		}

		return body.compactness;
	}

	/**
	 * The envelope that seals the body, when sealed.
	 */
	get confidentiality(): ConfidentialityInfo | undefined {
		const body = this.#body;
		if (body.layer !== "sealed") {
			return undefined;
		}

		return body.confidentiality;
	}

	/**
	 * A copy of the body DER of a cleartext body.
	 *
	 * @throws TightbeamTransportError `OpaqueBody`, with the capability the
	 * body needs on `layer`: `opener` for a sealed body, and `inflator` for a
	 * compressed one.
	 */
	plain(): Uint8Array {
		const body = this.#body;
		switch (body.layer) {
			case "plain":
				return new Uint8Array(body.der);
			case "compressed":
				throw ClientTransportError.opaqueBody("inflator");
			case "sealed":
				throw ClientTransportError.opaqueBody("opener");
			default: {
				const unknown: never = body;
				return unknown;
			}
		}
	}

	/**
	 * The body DER once each layer is reversed: open a sealed body with
	 * `opener`, then inflate a compressed one with `inflator`. The inflator
	 * admits the compactness info before the opener decrypts.
	 *
	 * @throws as {@link plain} and {@link HeldInflator.admit} do.
	 */
	async open(options: OpenOptions): Promise<Uint8Array> {
		const body = this.#body;
		switch (body.layer) {
			case "plain":
				return new Uint8Array(body.der);
			case "compressed": {
				const inflation = CarriedBody.admitted(options, body.compactness);
				const inflated = await inflation.inflate(new Uint8Array(body.data));
				return inflated;
			}
			case "sealed": {
				const opener = options.opener;
				if (opener === undefined) {
					throw ClientTransportError.opaqueBody("opener");
				}

				let inflation: Inflation | undefined;
				if (body.compactness !== undefined) {
					inflation = CarriedBody.admitted(options, body.compactness);
				}

				const envelopeDer = new Uint8Array(body.confidentiality.envelopeDer);
				const ciphertext = new Uint8Array(body.ciphertext);
				const plaintext = await opener.decrypt({
					envelopeDer,
					ciphertext,
				});
				if (inflation === undefined) {
					return plaintext;
				}

				const inflated = await inflation.inflate(plaintext);
				return inflated;
			}
			default: {
				const unknown: never = body;
				return unknown;
			}
		}
	}

	/**
	 * The inflation that the inflator of `options` admits for a body that
	 * `compactness` describes.
	 *
	 * @throws TightbeamTransportError `OpaqueBody`, which names `inflator` on `layer`, when `options` holds no
	 * inflator.
	 */
	private static admitted(options: OpenOptions, compactness: CompactnessInfo): Inflation {
		const inflator = options.inflator;
		if (inflator === undefined) {
			throw ClientTransportError.opaqueBody("inflator");
		}

		const held = HeldInflator.lent(inflator);
		const inflation = held.admit(compactness);
		return inflation;
	}
}

/**
 * The decoded fields of one frame, read once from the wasm inspect payload.
 */
class FrameFields {
	readonly version: Version;
	readonly id: Uint8Array;
	readonly order: bigint;
	readonly body: CarriedBody;
	readonly priority: MessagePriority | undefined;
	readonly lifetime: bigint | undefined;
	readonly previousFrame: PreviousFrame | undefined;
	readonly matrix: FrameMatrix | undefined;
	readonly messageIntegrity: DigestInfoView | undefined;
	readonly frameIntegrity: DigestInfoView | undefined;
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
		this.body = CarriedBody.of(inspected.body);
		this.priority = inspected.priority;
		this.lifetime = inspected.lifetime;
		this.previousFrame = FrameFields.digestOf(inspected.previousFrame);
		this.matrix = inspected.matrix;
		const messageIntegrity = inspected.messageIntegrity;
		this.messageIntegrity = FrameFields.digestOf(messageIntegrity);
		this.frameIntegrity = FrameFields.digestOf(inspected.frameIntegrity);
		this.signature = FrameFields.signatureOf(inspected.signature);
	}

	/**
	 * The view of a carried digest, or `undefined` for a field the frame
	 * omits.
	 */
	private static digestOf(carried: DigestInfo | undefined): DigestInfoView | undefined {
		if (carried === undefined) {
			return undefined;
		}

		const view = DigestInfoView.over(carried);
		return view;
	}

	/**
	 * The signature info with each `Oid` lent as a view.
	 */
	private static signatureOf(carried: CarriedSignature | undefined): SignatureInfo | undefined {
		if (carried === undefined) {
			return undefined;
		}

		const algorithmOid = OidView.over(carried.algorithmOid);
		const digestAlgorithmOid = OidView.over(carried.digestAlgorithmOid);

		const signature = { ...carried, algorithmOid, digestAlgorithmOid };
		return signature;
	}

	/**
	 * The fields of the frame that `assembly` decoded.
	 */
	static of(assembly: FrameAssembly): FrameFields {
		const fields = new FrameFields(assembly.summary());
		return fields;
	}
}

/**
 * What the engine answered for one preimage: its octets, or the refusal it
 * raised in their place.
 */
type PreimageAnswer = { readonly octets: Uint8Array } | { readonly refusal: unknown };

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
 * The preimages that the verification of one frame reads, read from the one
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
	 * The preimages of the frame that `assembly` decoded.
	 */
	static of(assembly: FrameAssembly): FramePreimages {
		const preimages = new FramePreimages(assembly);
		return preimages;
	}
}

/**
 * A tightbeam frame, which `Engine.frame` parses from received bytes and the
 * builder's `build()` makes. The bytes parse once, at construction, and the
 * frame lends each carried digest and identifier handle as a view that the
 * glue reclaims with the frame.
 */
export class Frame {
	readonly #parts: EngineParts;

	readonly #der: Uint8Array;

	readonly #fields: FrameFields;

	readonly #preimages: FramePreimages;

	private constructor(parts: EngineParts, der: Uint8Array, fields: FrameFields, preimages: FramePreimages) {
		this.#parts = parts;
		this.#der = der;
		this.#fields = fields;
		this.#preimages = preimages;
	}

	/**
	 * Parse a frame DER through the engine `parts`. The frame keeps its own
	 * copy, so a later write to `der` leaves the frame as it parsed.
	 *
	 * @throws TightbeamTransportError with the code of the engine's refusal,
	 * such as `SerializationError`, for bytes that are no well-formed frame.
	 *
	 * @internal
	 */
	static decode(parts: EngineParts, der: Uint8Array): Frame {
		// The constructor copies a Node `Buffer` too, whose `slice` is a view.
		const owned = new Uint8Array(der);
		using assembly = parts.glue.FrameAssembly.decode(owned);

		const fields = FrameFields.of(assembly);
		const preimages = FramePreimages.of(assembly);
		const frame = new Frame(parts, owned, fields, preimages);
		return frame;
	}

	/**
	 * Parse the DER of a response frame through the engine `parts`, or
	 * answer `undefined` when the peer returned no response frame.
	 *
	 * @throws TightbeamTransportError as {@link decode} does.
	 *
	 * @internal
	 */
	static response(parts: EngineParts, der: Uint8Array | undefined): Frame | undefined {
		if (der === undefined) {
			return undefined;
		}

		const frame = Frame.decode(parts, der);
		return frame;
	}

	/**
	 * A copy of the frame DER, so a write to it leaves this frame unchanged.
	 */
	toDer(): Uint8Array {
		const der = new Uint8Array(this.#der);
		return der;
	}

	/**
	 * The protocol version of the frame, which bounds the metadata fields it carries.
	 */
	get version(): Version {
		const version = this.#fields.version;
		return version;
	}

	/**
	 * A copy of the opaque message identifier, so a write to it leaves this
	 * frame unchanged.
	 */
	get id(): Uint8Array {
		const id = new Uint8Array(this.#fields.id);
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
		const order = this.#fields.order;
		return order;
	}

	/**
	 * A copy of the octets the frame carries as its body, so a write to it
	 * leaves what {@link open} decodes unchanged: the body DER, the
	 * compressed octets when {@link compressed}, or the ciphertext when
	 * {@link confidential}.
	 */
	get bodyDer(): Uint8Array {
		const bodyDer = new Uint8Array(this.#fields.body.octets);
		return bodyDer;
	}

	/**
	 * The frame carries a non-repudiation signature.
	 */
	get signed(): boolean {
		const signed = this.#fields.signature !== undefined;
		return signed;
	}

	/**
	 * The metadata commits to the body (message integrity).
	 */
	get messageIntegrity(): boolean {
		const messageIntegrity = this.#fields.messageIntegrity !== undefined;
		return messageIntegrity;
	}

	/**
	 * The envelope is witnessed (frame integrity).
	 */
	get frameIntegrity(): boolean {
		const frameIntegrity = this.#fields.frameIntegrity !== undefined;
		return frameIntegrity;
	}

	/**
	 * The body is compressed.
	 */
	get compressed(): boolean {
		const compressed = this.#fields.body.compactness !== undefined;
		return compressed;
	}

	/**
	 * The body is encrypted.
	 */
	get confidential(): boolean {
		const confidential = this.#fields.body.confidentiality !== undefined;
		return confidential;
	}

	/**
	 * The carried message-commitment digest, when committed.
	 */
	get messageIntegrityInfo(): DigestInfoView | undefined {
		const messageIntegrityInfo = this.#fields.messageIntegrity;
		return messageIntegrityInfo;
	}

	/**
	 * The carried witness digest, when witnessed.
	 */
	get frameIntegrityInfo(): DigestInfoView | undefined {
		const frameIntegrityInfo = this.#fields.frameIntegrity;
		return frameIntegrityInfo;
	}

	/**
	 * A copy of the carried compactness info, when compressed, so a write to
	 * it leaves what {@link open} inflates with unchanged.
	 */
	get compactnessInfo(): CompactnessInfo | undefined {
		const carried = this.#fields.body.compactness;
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
		const carried = this.#fields.body.confidentiality;
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
		const carried = this.#fields.signature;
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
		const priority = this.#fields.priority;
		return priority;
	}

	/**
	 * Time-to-live in seconds, when present (V2+).
	 */
	get lifetime(): bigint | undefined {
		const lifetime = this.#fields.lifetime;
		return lifetime;
	}

	/**
	 * Parent-frame link by content digest, when present (V2+).
	 */
	get previousFrame(): PreviousFrame | undefined {
		const previousFrame = this.#fields.previousFrame;
		return previousFrame;
	}

	/**
	 * A copy of the N×N control matrix, when present (V3+), so a write to it
	 * leaves this frame unchanged.
	 */
	get matrix(): FrameMatrix | undefined {
		const carried = this.#fields.matrix;
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
		const tbs = this.#preimages.tbs.copy();
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
		const prehash = this.#preimages.prehash.copy();
		return prehash;
	}

	/**
	 * The frame-integrity (witness) preimage: the envelope bytes the
	 * carried witness digest is computed over.
	 */
	witnessInput(): Uint8Array {
		const witness = this.#preimages.witness.copy();
		return witness;
	}

	/**
	 * The message-commitment preimage over the carried body DER, under `salt`,
	 * the parse of the octets that `withMessageHasher` received.
	 *
	 * @throws TightbeamTransportError `OpaqueBody` for a sealed or compressed
	 * body, and `SerializationError` for a body that is not one DER value.
	 */
	commitmentInput(salt: CommitmentSalt): Uint8Array {
		const bodyDer = this.#fields.body.plain();
		const commitmentInput = salt.preimage(bodyDer);
		return commitmentInput;
	}

	/**
	 * Verify the non-repudiation signature of the frame through `verifier`,
	 * a {@link Secp256k1VerifyingKey} or a {@link FrameVerifier} of any scheme.
	 *
	 * @throws as a rejection, when the frame is unsigned, the algorithm
	 * differs, or the signature does not verify.
	 */
	async verify(verifier: FrameVerifier): Promise<void> {
		await verifier.verifyFrame(this);
	}

	/**
	 * Check the carried witness digest by recomputing it with `hasher`
	 * (profile SHA3-256 by default).
	 */
	async frameIntegrityVerdict(hasher: Hasher = this.#parts.sha3_256): Promise<IntegrityVerdict> {
		const carried = this.#fields.frameIntegrity;
		if (carried === undefined) {
			return "absent";
		}

		const preimage = this.witnessInput();
		const verdict = await Frame.verdictOf(carried, hasher, preimage);
		return verdict;
	}

	/**
	 * Check the carried commitment against the disclosed `salt` under `hasher`, the profile SHA3-256 by default. It
	 * covers the uncompressed body DER, so open a sealed or compressed frame under a codec whose `decode` answers its
	 * input, and check a present `messageIntegrityInfo` with `engine.opening(salt, bodyDer).verify`.
	 *
	 * @throws as {@link commitmentInput} does.
	 */
	async messageCommitmentVerdict(
		salt: CommitmentSalt,
		hasher: Hasher = this.#parts.sha3_256,
	): Promise<IntegrityVerdict> {
		const carried = this.#fields.messageIntegrity;
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
	): Promise<IntegrityVerdict> {
		const recomputed = await hasher.digest(preimage);
		const verdict = carried.verdict(hasher.algorithmOid, recomputed);
		return verdict;
	}

	/**
	 * Reverse the layers this frame carries, and decode the body under `codec`.
	 * This is the one decode of a frame body.
	 *
	 * @throws TightbeamTransportError `OpaqueBody` or `CompactnessRefused`, and
	 * the refusal of the opener, the inflator, or the codec.
	 */
	async open<T>(codec: MessageCodec<T>, options: OpenOptions = {}): Promise<T> {
		const bodyDer = await this.#fields.body.open(options);
		const message = codec.decode(bodyDer);
		return message;
	}
}
