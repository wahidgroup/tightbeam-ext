/**
 * The security layers of a frame build, each of which declares its field to
 * the composer and installs its artifact in protocol order.
 */

import type { CommitmentSalt, FrameAssembly, FrameComposer } from "#wasm";

import type { BodyCompressor } from "../compress.js";
import type { BodyEncryptor, Hasher, Signatory } from "../crypto.js";
import type { EngineParts } from "../engine.js";
import type { OidName } from "../views.js";
import type { Assembled } from "./assembly.js";
import { HeldCompressor } from "../compress.js";
import { HeldHasher } from "../crypto.js";

/**
 * The octets of the plain-digest salt, for a commitment that names none.
 */
const EMPTY_SALT = new Uint8Array();

/**
 * What a layer reads from the build that installs it.
 */
export interface BuildInputs {
	/**
	 * The engine of the build.
	 */
	readonly parts: EngineParts;

	/**
	 * The content type the encryptor seals the body as.
	 */
	readonly contentOid: OidName;
}

/**
 * One security layer of a frame.
 */
interface Layer {
	/**
	 * Declare the field this layer installs, so the engine counts it in the
	 * version floor before any layer runs.
	 */
	declare(composer: FrameComposer): void;

	/**
	 * Reserve what this layer spends for one build, before any layer acts.
	 */
	reserve?(): void;

	/**
	 * Install the artifact of this layer on `assembled`, which the step
	 * consumes, and answer the next frame.
	 */
	install(assembled: Assembled, inputs: BuildInputs): Promise<Assembled>;

	/**
	 * Release the reservation of a build that a layer or the encode refused.
	 */
	release?(): void;

	/**
	 * Spend the reservation of a build that encoded its frame.
	 */
	settle?(): void;
}

/**
 * The message commitment: a digest of the body DER under a salt.
 */
class CommitmentLayer implements Layer {
	readonly #hasher: HeldHasher;

	/**
	 * The salt this layer took, or `undefined` for a plain digest. While a build holds the salt, and once it spends it,
	 * this is an empty shell that refuses a reserve with `CommitmentSpent`.
	 */
	#salt: CommitmentSalt | undefined;

	/**
	 * The salt that one build reserved, from its reserve to its release or
	 * settle.
	 */
	#reserved: CommitmentSalt | undefined;

	/**
	 * Copy the algorithm of `hasher` before the take, so a refused copy leaves the caller its salt.
	 */
	constructor(hasher: Hasher, salt: CommitmentSalt | undefined) {
		this.#hasher = new HeldHasher(hasher);
		this.#salt = salt?.take();
	}

	declare(composer: FrameComposer): void {
		composer.declareMessageIntegrity();
	}

	/**
	 * Move the salt into the reservation of this build.
	 *
	 * @throws TightbeamTransportError `CommitmentSpent` when another build
	 * holds or spent the salt.
	 */
	reserve(): void {
		this.#reserved = this.#salt?.take();
	}

	install(assembled: Assembled, inputs: BuildInputs): Promise<Assembled> {
		const hasher = this.#hasher;
		const digesting = async (live: FrameAssembly): Promise<Uint8Array> => {
			const preimage = this.#preimage(live, inputs);
			const digest = await hasher.digest(preimage);
			return digest;
		};

		const installed = assembled.after(digesting, (live, digest) => {
			using algorithmOid = hasher.algorithmOid.clone();
			return live.withMessageIntegrity(algorithmOid, digest);
		});
		return installed;
	}

	release(): void {
		const reserved = this.#reserved;
		if (reserved !== undefined) {
			this.#salt?.free();
			this.#salt = reserved;
			this.#reserved = undefined;
		}
	}

	settle(): void {
		this.#reserved?.free();
		this.#reserved = undefined;
	}

	/**
	 * The commitment preimage of `live` under the salt the build reserved, or
	 * under the plain-digest salt.
	 */
	#preimage(live: FrameAssembly, inputs: BuildInputs): Uint8Array {
		const held = this.#reserved;
		if (held !== undefined) {
			const preimage = live.commitmentPreimage(held);
			return preimage;
		}

		using plain = inputs.parts.glue.CommitmentSalt.parse(EMPTY_SALT);
		const preimage = live.commitmentPreimage(plain);
		return preimage;
	}
}

/**
 * The body compression, which runs after the commitment and before the seal.
 */
class CompressionLayer implements Layer {
	readonly #compressor: HeldCompressor;

	constructor(compressor: BodyCompressor) {
		this.#compressor = new HeldCompressor(compressor);
	}

	declare(): void {
		// The compactness info is a field of every version, so the floor of
		// every version admits it.
	}

	install(assembled: Assembled): Promise<Assembled> {
		const compressor = this.#compressor;
		const installed = assembled.after(
			(live) => compressor.compress(live.body),
			(live, compressed) => {
				using algorithmOid = compressor.algorithmOid.clone();
				const { data, parametersDer } = compressed;
				return live.withCompactness(algorithmOid, data, parametersDer);
			},
		);
		return installed;
	}
}

/**
 * The body encryption, which seals the body the frame holds: the compressed
 * octets when a compression ran.
 */
class EncryptionLayer implements Layer {
	readonly #encryptor: BodyEncryptor;

	constructor(encryptor: BodyEncryptor) {
		this.#encryptor = encryptor;
	}

	declare(composer: FrameComposer): void {
		composer.declareConfidentiality();
	}

	install(assembled: Assembled, inputs: BuildInputs): Promise<Assembled> {
		const encryptor = this.#encryptor;
		const installed = assembled.after(
			(live) => encryptor.encrypt(live.body, inputs.contentOid),
			(live, sealed) => live.withConfidentiality(sealed),
		);
		return installed;
	}
}

/**
 * The frame integrity witness, which covers the final metadata.
 */
class WitnessLayer implements Layer {
	readonly #hasher: HeldHasher;

	constructor(hasher: Hasher) {
		this.#hasher = new HeldHasher(hasher);
	}

	declare(composer: FrameComposer): void {
		composer.declareFrameIntegrity();
	}

	install(assembled: Assembled): Promise<Assembled> {
		const hasher = this.#hasher;
		const installed = assembled.after(
			(live) => hasher.digest(live.witnessPreimage()),
			(live, digest) => {
				using algorithmOid = hasher.algorithmOid.clone();
				return live.withWitness(algorithmOid, digest);
			},
		);
		return installed;
	}
}

/**
 * The non-repudiation signature, which covers the witness.
 */
class SignatureLayer implements Layer {
	readonly #signatory: Signatory;

	constructor(signatory: Signatory) {
		this.#signatory = signatory;
	}

	declare(composer: FrameComposer): void {
		composer.declareNonrepudiation();
	}

	install(assembled: Assembled): Promise<Assembled> {
		const signed = assembled.sign(this.#signatory);
		return signed;
	}
}

/**
 * The slot of each layer, in the protocol order of tightbeam's install
 * steps: the commitment, the compression, the encryption, the witness, and
 * the signature.
 */
const PROTOCOL_ORDER = ["commitment", "compression", "encryption", "witness", "signature"] as const;

/**
 * The slot of one layer.
 */
type LayerSlot = (typeof PROTOCOL_ORDER)[number];

/**
 * The layer each slot holds.
 */
type Slots = Partial<Record<LayerSlot, Layer>>;

/**
 * The security layers a builder holds, at most one in each slot, which run
 * in protocol order.
 */
export class SecurityLayers {
	readonly #slots: Slots;

	private constructor(slots: Slots) {
		this.#slots = slots;
	}

	/**
	 * No layer: a cleartext frame.
	 */
	static none(): SecurityLayers {
		const none = new SecurityLayers({});
		return none;
	}

	/**
	 * These layers, with the commitment of `hasher` under the salt the layer takes out of `salt`, or a plain digest
	 * without one.
	 *
	 * @throws TightbeamTransportError `CommitmentSpent` when the salt moved out of `salt` already.
	 * @throws the refusal of `hasher.algorithmOid.clone()`, such as for a freed `Oid`, and `salt` keeps its salt.
	 */
	withCommitment(hasher: Hasher, salt: CommitmentSalt | undefined): SecurityLayers {
		const layers = this.#with("commitment", new CommitmentLayer(hasher, salt));
		return layers;
	}

	/**
	 * These layers, with the compression of `compressor`.
	 */
	withCompression(compressor: BodyCompressor): SecurityLayers {
		const layer = new CompressionLayer(compressor);
		const layers = this.#with("compression", layer);
		return layers;
	}

	/**
	 * These layers, with the seal of `encryptor`.
	 */
	withEncryption(encryptor: BodyEncryptor): SecurityLayers {
		const layers = this.#with("encryption", new EncryptionLayer(encryptor));
		return layers;
	}

	/**
	 * These layers, with the witness of `hasher`.
	 */
	withWitness(hasher: Hasher): SecurityLayers {
		const layers = this.#with("witness", new WitnessLayer(hasher));
		return layers;
	}

	/**
	 * These layers, with the signature of `signatory`.
	 */
	withSignature(signatory: Signatory): SecurityLayers {
		const layers = this.#with("signature", new SignatureLayer(signatory));
		return layers;
	}

	/**
	 * Declare every layer to `composer`.
	 */
	declare(composer: FrameComposer): void {
		for (const layer of this.#inOrder()) {
			layer.declare(composer);
		}
	}

	/**
	 * Reserve every layer, install each one in protocol order on the frame
	 * that `compose` assembles, and answer the DER of the finished frame.
	 *
	 * A refusal releases what this build reserved, so a retry can build. An
	 * encoded frame settles every reservation.
	 */
	async encode(compose: () => Assembled, inputs: BuildInputs): Promise<Uint8Array> {
		const layers = this.#inOrder();
		const reserved: Layer[] = [];
		let der: Uint8Array;
		try {
			for (const layer of layers) {
				layer.reserve?.();
				reserved.push(layer);
			}

			let current = compose();
			for (const layer of layers) {
				current = await layer.install(current, inputs);
			}

			der = current.encode();
		} catch (refusal) {
			for (const layer of reserved) {
				layer.release?.();
			}

			throw refusal;
		}

		for (const layer of layers) {
			layer.settle?.();
		}

		return der;
	}

	/**
	 * The layers held, in protocol order.
	 */
	#inOrder(): Layer[] {
		const held = PROTOCOL_ORDER.map((slot) => this.#slots[slot]);
		const layers = held.filter((layer) => layer !== undefined);
		return layers;
	}

	/**
	 * These layers with `layer` in `slot`, in place of the layer it held.
	 */
	#with(slot: LayerSlot, layer: Layer): SecurityLayers {
		const slots: Slots = { ...this.#slots, [slot]: layer };
		const layers = new SecurityLayers(slots);
		return layers;
	}
}
