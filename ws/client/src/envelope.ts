/**
 * The typed message envelope, which declares the layers of a frame once for both directions, as the envelopes section
 * of `docs/ws-client.md` describes.
 */

import type { BodyCompressor, BodyInflator } from "./compress.js";
import type { BodyDecryptor, BodyEncryptor, FrameVerifier, Signatory } from "./crypto.js";
import type { EngineParts } from "./engine.js";
import type { Frame } from "./frame.js";
import type { MessageCodec } from "./message.js";
import { FrameBuilder } from "./builder/builder.js";
import { HeldCompressor, HeldInflator } from "./compress.js";
import { ClientTransportError } from "./errors.js";
import { HeldCodec } from "./message.js";

/**
 * The halves of authenticity: the signatory that signs each frame the
 * envelope builds, and the verifier that each frame it unwraps MUST verify
 * under.
 */
export interface SignatureHalves {
	readonly signer?: Signatory;
	readonly verifier?: FrameVerifier;
}

/**
 * The halves of confidentiality: the encryptor that seals each frame the
 * envelope builds, and the decryptor that opens each frame it unwraps.
 */
export interface SealHalves {
	readonly sealer?: BodyEncryptor;
	readonly opener?: BodyDecryptor;
}

/**
 * The halves of compression: the compressor of each frame the envelope
 * builds, and the inflator of each compressed frame it unwraps.
 */
export interface CompressionHalves {
	readonly compressor?: BodyCompressor;
	readonly inflator?: BodyInflator;
}

/**
 * `true` when the halves `H` hold the member `K` of type `V`.
 */
type Holds<H, K extends PropertyKey, V> = H extends Readonly<Record<K, V>> ? true : false;

/**
 * `true` when both `A` and `B` are `true`.
 */
type Both<A extends boolean, B extends boolean> = A extends true ? B : false;

/**
 * The declared layers, each with the halves its declaration named.
 */
interface Layers {
	readonly signature?: SignatureHalves;
	readonly seal?: SealHalves;
	readonly compressor?: HeldCompressor;
	readonly inflator?: HeldInflator;
}

/**
 * The key of the record of which directions an envelope runs. A symbol key
 * keeps the record in the emitted declarations, where a private member loses
 * its type.
 */
declare const DIRECTIONS: unique symbol;

/**
 * A typed message envelope: the codec plus its security and transport layers, immutable and reusable across every frame
 * of a conversation. `Sends` records whether each declared layer holds the send half that {@link frame} needs, and
 * `Receives` records the receive halves that {@link unwrap} needs. The envelopes section of `docs/ws-client.md` shows
 * an envelope that frames and unwraps a message.
 */
export class Envelope<T, Sends extends boolean = true, Receives extends boolean = true> {
	/**
	 * Which directions the declared layers can run, recorded in the type
	 * alone.
	 */
	declare readonly [DIRECTIONS]: [Sends, Receives];

	readonly #parts: EngineParts;

	readonly #codec: MessageCodec<T>;

	readonly #layers: Layers;

	private constructor(parts: EngineParts, codec: MessageCodec<T>, layers: Layers) {
		this.#parts = parts;
		this.#codec = codec;
		this.#layers = layers;
	}

	/**
	 * Begin a typed message envelope over `codec` through the engine `parts`,
	 * with no layers declared: declare the layers once (`signed`, `sealed`,
	 * `compressed`), then build with `frame(message)` and receive with
	 * `unwrap(frame)`. `unwrap` enforces the declared layers.
	 *
	 * @internal
	 */
	static over<T>(parts: EngineParts, codec: MessageCodec<T>): Envelope<T> {
		const held = HeldCodec.of(codec);
		const begun = new Envelope<T>(parts, held, {});
		return begun;
	}

	#with<S extends boolean, R extends boolean>(patch: Partial<Layers>): Envelope<T, S, R> {
		const layers = { ...this.#layers, ...patch };
		const next = new Envelope<T, S, R>(this.#parts, this.#codec, layers);
		return next;
	}

	/**
	 * Declare authenticity: `frame()` signs with `halves.signer`, and
	 * `unwrap()` REQUIRES a signature that verifies under `halves.verifier`.
	 * A party without the signing key names the verifier alone, and a wallet
	 * or a passkey that cannot verify names the signer alone.
	 */
	signed<H extends SignatureHalves>(
		halves: H,
	): Envelope<T, Both<Sends, Holds<H, "signer", Signatory>>, Both<Receives, Holds<H, "verifier", FrameVerifier>>> {
		const { signer, verifier } = halves;
		const next = this.#with<
			Both<Sends, Holds<H, "signer", Signatory>>,
			Both<Receives, Holds<H, "verifier", FrameVerifier>>
		>({ signature: { signer, verifier } });
		return next;
	}

	/**
	 * Declare confidentiality: `frame()` seals the body with `halves.sealer`,
	 * and `unwrap()` REJECTS a cleartext frame and opens a sealed one with
	 * `halves.opener`. `Aes256Gcm` is both halves, and an HPKE pair splits
	 * between the publisher and the recipient.
	 */
	sealed<H extends SealHalves>(
		halves: H,
	): Envelope<T, Both<Sends, Holds<H, "sealer", BodyEncryptor>>, Both<Receives, Holds<H, "opener", BodyDecryptor>>> {
		const { sealer, opener } = halves;
		const next = this.#with<
			Both<Sends, Holds<H, "sealer", BodyEncryptor>>,
			Both<Receives, Holds<H, "opener", BodyDecryptor>>
		>({ seal: { sealer, opener } });
		return next;
	}

	/**
	 * Declare compression: `frame()` compresses the body with
	 * `halves.compressor`, and `unwrap()` inflates a compressed frame with
	 * `halves.inflator`. Compression is a transport optimization rather than a
	 * security property, so an uncompressed received frame still unwraps.
	 */
	compressed(halves: CompressionHalves): Envelope<T, Sends, Receives> {
		const { compressor, inflator } = halves;
		let patch: Pick<Layers, "compressor" | "inflator"> = {};
		if (compressor !== undefined) {
			patch = { ...patch, compressor: new HeldCompressor(compressor) };
		}
		if (inflator !== undefined) {
			patch = { ...patch, inflator: HeldInflator.copyOf(inflator) };
		}

		const next = this.#with<Sends, Receives>(patch);
		return next;
	}

	/**
	 * Begin a frame carrying `message` with every declared layer applied,
	 * returning the builder for metadata and `build()`.
	 *
	 * @throws TightbeamTransportError `EnvelopeSender` when a declared layer
	 * holds no send half, which the type refuses for a TypeScript caller.
	 */
	frame(this: Envelope<T, true, Receives>, message: T): FrameBuilder {
		const { signature, seal, compressor } = this.#layers;
		const signer = signature?.signer;
		const sealer = seal?.sealer;
		const unsigned = signature !== undefined && signer === undefined;
		const unsealed = seal !== undefined && sealer === undefined;
		if (unsigned || unsealed) {
			throw ClientTransportError.envelopeSender();
		}

		let builder = FrameBuilder.message(this.#parts, this.#codec, message);
		if (compressor !== undefined) {
			builder = builder.withCompressor(compressor);
		}
		if (sealer !== undefined) {
			builder = builder.withEncryptor(sealer);
		}
		if (signer !== undefined) {
			builder = builder.withSigner(signer);
		}

		return builder;
	}

	/**
	 * Verify, open, inflate, and decode a received frame under the declared
	 * layers, as the envelopes section of `docs/ws-client.md` describes.
	 *
	 * @throws TightbeamTransportError `EnvelopeUnsigned` or `EnvelopeCleartext`
	 * for a declared layer the frame lacks, and as {@link Frame.open} does.
	 */
	async unwrap(this: Envelope<T, Sends, true>, received: Frame): Promise<T> {
		const { signature, seal, inflator } = this.#layers;
		const verifier = signature?.verifier;
		const opener = seal?.opener;
		const unverified = signature !== undefined && verifier === undefined;
		const unopened = seal !== undefined && opener === undefined;
		if (unverified || unopened) {
			throw ClientTransportError.envelopeReceiver();
		}

		if (verifier !== undefined) {
			if (!received.signed) {
				throw ClientTransportError.envelopeUnsigned();
			}

			await received.verify(verifier);
		}
		if (opener !== undefined && !received.confidential) {
			throw ClientTransportError.envelopeCleartext();
		}

		const message = await received.open(this.#codec, { opener, inflator });
		return message;
	}

	/**
	 * The envelope declares authenticity: frames it builds are signed,
	 * and frames it unwraps MUST be.
	 */
	get authenticated(): boolean {
		const declared = this.#layers.signature !== undefined;
		return declared;
	}

	/**
	 * The envelope declares confidentiality: frames it builds are
	 * sealed, and frames it unwraps MUST be.
	 */
	get confidential(): boolean {
		const declared = this.#layers.seal !== undefined;
		return declared;
	}
}
