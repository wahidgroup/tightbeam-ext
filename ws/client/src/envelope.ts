/**
 * Composed frame processing: declare the layers once - serialization,
 * compression, sealing, signing - and use the same declaration in both
 * directions.
 */

import type {
	BodyDecryptor,
	BodyEncryptor,
	FrameVerifier,
	Signatory,
} from "./crypto.js";
import type { ValidationCode } from "./builder/errors.js";
import type { BodyCompressor, BodyInflator } from "./compress.js";
import type { EngineParts } from "./engine.js";
import type { Frame } from "./frame.js";
import type { MessageCodec } from "./message.js";
import { FrameBuilder } from "./builder/builder.js";
import { ValidationError } from "./builder/errors.js";
import { HeldCompressor, HeldInflator } from "./compress.js";
import { HeldCodec } from "./message.js";

/**
 * The declared layers. Each direction is optional so one-sided parties
 * compose only their half: a subscriber holds a verifying key and a
 * decryptor, a publisher a signatory and an encryptor. Symmetric
 * implementations (`Aes256Gcm`, the engine `ZstdCompression`) declare both at
 * once.
 */
interface Layers {
	readonly signer?: Signatory;
	readonly verifier?: FrameVerifier;
	readonly sealer?: BodyEncryptor;
	readonly opener?: BodyDecryptor;
	readonly compressor?: BodyCompressor;
	readonly inflator?: BodyInflator;
}

/**
 * A typed message envelope: the codec plus the declared security and
 * transport layers, immutable and reusable across every frame of a
 * conversation.
 *
 * ```ts
 * const notes = engine
 *     .envelope(Notes)
 *     .signed(publisherKey)
 *     .sealed(engine.aes256Gcm({ key: topicKey, keyId: topicKeyId }));
 *
 * const sent = await notes.frame(note).withId("note-1").build();
 * const received = await notes.unwrap(relayed); // Note
 * ```
 */
export class Envelope<T> {
	readonly #parts: EngineParts;

	private constructor(
		parts: EngineParts,
		private readonly codec: MessageCodec<T>,
		private readonly layers: Layers,
	) {
		this.#parts = parts;
	}

	/**
	 * The refusal of a frame that breaks a declared layer, with the code
	 * `code`.
	 */
	private static refusal(
		code: ValidationCode,
		message: string,
	): ValidationError {
		const issues = [{ path: "envelope", message }];
		const refused = new ValidationError(code, issues);
		return refused;
	}

	/**
	 * Begin a typed message envelope over `codec` through the engine `parts`,
	 * with no layers declared: declare the layers once (`signed`, `sealed`,
	 * `compressed`), then build with `frame(message)` and receive with
	 * `unwrap(frame)`. `unwrap` enforces the declared layers.
	 */
	static over<T>(parts: EngineParts, codec: MessageCodec<T>): Envelope<T> {
		const held = HeldCodec.of(codec);
		const begun = new Envelope(parts, held, {});
		return begun;
	}

	private with(patch: Partial<Layers>): Envelope<T> {
		const next = new Envelope(this.#parts, this.codec, {
			...this.layers,
			...patch,
		});
		return next;
	}

	/**
	 * Declare authenticity with the wrap-side capability: `frame()` signs
	 * with `signatory`, and `unwrap()` REQUIRES a valid signature.
	 *
	 * A signatory with {@link Signatory.verifier} (profile
	 * `Secp256k1SigningKey`) declares both directions. Any other
	 * {@link Signatory} needs {@link verified} alongside it, or must
	 * expose its own `verifier`, before `unwrap()` can check the signature.
	 */
	signed(signatory: Signatory): Envelope<T> {
		const next = this.with({ signer: signatory });
		return next;
	}

	/**
	 * Declare authenticity with the unwrap-side capability: `unwrap()`
	 * REQUIRES a signature verifying under `verifier`. The read-only half
	 * of {@link signed}, for parties without the signing key.
	 */
	verified(verifier: FrameVerifier): Envelope<T> {
		const next = this.with({ verifier });
		return next;
	}

	/**
	 * Declare confidentiality: `frame()` seals the body, and `unwrap()`
	 * REJECTS a cleartext frame. `keys` contributes whichever halves it
	 * implements - `Aes256Gcm` both, an HPKE pair one each.
	 */
	sealed(keys: BodyEncryptor | BodyDecryptor): Envelope<T> {
		let patch: Partial<Layers> = {};
		if ("encrypt" in keys) {
			patch = { ...patch, sealer: keys };
		}
		if ("decrypt" in keys) {
			patch = { ...patch, opener: keys };
		}

		const next = this.with(patch);
		return next;
	}

	/**
	 * Declare compression: `frame()` compresses the body, and `unwrap()`
	 * inflates a compressed one. Compression is a transport optimization,
	 * not a security property, so an uncompressed received frame still unwraps.
	 */
	compressed(compression: BodyCompressor | BodyInflator): Envelope<T> {
		let patch: Partial<Layers> = {};
		if ("compress" in compression) {
			const compressor = new HeldCompressor(compression);
			patch = { ...patch, compressor };
		}
		if ("decompress" in compression) {
			const inflator = new HeldInflator(compression);
			patch = { ...patch, inflator };
		}

		const next = this.with(patch);
		return next;
	}

	/**
	 * Begin a frame carrying `message` with every declared layer applied,
	 * returning the builder for metadata and `build()`.
	 *
	 * @throws ValidationError when a declared layer is missing its
	 * wrap-side capability (a verify-only or open-only envelope MUST NOT
	 * silently send unsigned or cleartext frames).
	 */
	frame(message: T): FrameBuilder {
		if (this.authenticityDeclared() && this.layers.signer === undefined) {
			throw Envelope.refusal(
				"ENVELOPE_SIGNER",
				"The envelope declares authenticity but has no signatory: " +
					"declare signed(signatory) to build frames",
			);
		}
		if (this.sealedDeclared() && this.layers.sealer === undefined) {
			throw Envelope.refusal(
				"ENVELOPE_SEALER",
				"The envelope declares confidentiality but has no encryptor: " +
					"declare sealed(encryptor) to build frames",
			);
		}

		const begun = FrameBuilder.of(this.#parts);
		let builder = begun.withMessage(this.codec, message);
		if (this.layers.compressor !== undefined) {
			builder = builder.withCompressor(this.layers.compressor);
		}
		if (this.layers.sealer !== undefined) {
			builder = builder.withEncryptor(this.layers.sealer);
		}
		if (this.layers.signer !== undefined) {
			builder = builder.withSigner(this.layers.signer);
		}

		return builder;
	}

	/**
	 * Reverse the declared layers on a received frame: verify, open,
	 * inflate, decode - and enforce them.
	 *
	 * - The envelope decides policy: a declared signature MUST verify, and a
	 *   declared seal MUST be present.
	 * - The frame decides how its body opens, through {@link Frame.open}.
	 *
	 * @throws ValidationError in each of these cases:
	 *
	 * - A declared signature or seal is absent (a downgrade).
	 * - A declared layer is missing its unwrap-side capability.
	 * - The frame carries a layer the envelope cannot reverse.
	 *
	 * @throws when the signature does not verify, the opener rejects the
	 * ciphertext, the inflator rejects the body, or the codec rejects the
	 * decoded bytes.
	 */
	async unwrap(received: Frame): Promise<T> {
		this.checkAuthenticity(received);

		if (this.sealedDeclared() && !received.confidential) {
			throw Envelope.refusal(
				"ENVELOPE_CLEARTEXT",
				"The envelope declares confidentiality but the frame body " +
					"is cleartext: refusing the downgrade",
			);
		}

		const message = await received.open(this.codec, {
			opener: this.layers.opener,
			inflator: this.layers.inflator,
		});
		return message;
	}

	/**
	 * The envelope declares authenticity: frames it builds are signed,
	 * and frames it unwraps MUST verify.
	 */
	get authenticated(): boolean {
		const declared = this.authenticityDeclared();
		return declared;
	}

	/**
	 * The envelope declares confidentiality: frames it builds are
	 * sealed, and frames it unwraps MUST be.
	 */
	get confidential(): boolean {
		const declared = this.sealedDeclared();
		return declared;
	}

	/**
	 * Authenticity is declared by either half.
	 */
	private authenticityDeclared(): boolean {
		const { signer, verifier } = this.layers;
		const declared = signer !== undefined || verifier !== undefined;
		return declared;
	}

	/**
	 * Confidentiality is declared by either half.
	 */
	private sealedDeclared(): boolean {
		const { sealer, opener } = this.layers;
		const declared = sealer !== undefined || opener !== undefined;
		return declared;
	}

	/**
	 * The verifier for `unwrap()`: the explicit declaration, or the
	 * signatory's own verify half, resolved at the unwrap.
	 */
	private resolveVerifier(): FrameVerifier | undefined {
		if (this.layers.verifier !== undefined) {
			return this.layers.verifier;
		}

		return this.layers.signer?.verifier;
	}

	/**
	 * Enforce declared authenticity: the frame MUST carry a signature
	 * verifying under the declared (or derived) verifier.
	 */
	private checkAuthenticity(received: Frame): void {
		if (!this.authenticityDeclared()) {
			return;
		}

		const verifier = this.resolveVerifier();
		if (verifier === undefined) {
			throw Envelope.refusal(
				"ENVELOPE_VERIFIER",
				"The envelope declares authenticity but its signatory " +
					"exposes no verifier: declare verified(verifier) to " +
					"unwrap frames",
			);
		}

		if (!received.signed) {
			throw Envelope.refusal(
				"ENVELOPE_UNSIGNED",
				"The envelope declares authenticity but the frame is " +
					"unsigned: refusing the downgrade",
			);
		}

		received.verify(verifier);
	}
}
