/**
 * Composed frame processing: declare the layers once - serialization,
 * compression, sealing, signing - and use the same declaration in both
 * directions.
 *
 * The frame format fixes the layering, so an envelope takes declarations
 * rather than a free-form pipeline. `frame()` begins a builder with them
 * applied; `unwrap()` reverses them and ENFORCES them: a declared
 * signature or seal that a received frame lacks REJECTS instead of degrading,
 * so a peer cannot downgrade the conversation by omission.
 */

import type { FrameCodec } from "./builder/codec.js";
import type { BodyCompressor, BodyInflator } from "./compress.js";
import type {
	BodyDecryptor,
	BodyEncryptor,
	Secp256k1VerifyingKey,
	Signatory,
} from "./crypto.js";
import type { Frame } from "./frame.js";
import type { MessageCodec } from "./message.js";
import { FrameBuilder } from "./builder/builder.js";
import { ValidationError } from "./builder/errors.js";
import { Secp256k1SigningKey } from "./crypto.js";

/**
 * The declared layers. Each direction is optional so one-sided parties
 * compose only their half: a subscriber holds a verifying key and a
 * decryptor, a publisher a signatory and an encryptor. Symmetric
 * implementations (`Aes256Gcm`, `ZstdCompression`) declare both at once.
 */
interface Layers {
	readonly signer?: Signatory;
	readonly verifier?: Secp256k1VerifyingKey;
	readonly sealer?: BodyEncryptor;
	readonly opener?: BodyDecryptor;
	readonly compressor?: BodyCompressor;
	readonly inflator?: BodyInflator;
}

/**
 * A layer-enforcement failure.
 */
function envelopeError(code: string, message: string): ValidationError {
	const error = new ValidationError(code, [{ path: "envelope", message }]);
	return error;
}

/**
 * A typed message envelope: the codec plus the declared security and
 * transport layers, immutable and reusable across every frame of a
 * conversation.
 *
 * ```ts
 * const notes = envelope(Notes)
 *     .signed(publisherKey)
 *     .sealed(Aes256Gcm.fromKey(topicKey));
 *
 * const sent = await notes.frame(note).withId("note-1").build();
 * const received = await notes.unwrap(relayed); // Note
 * ```
 */
export class Envelope<T> {
	private constructor(
		private readonly frameCodec: FrameCodec,
		private readonly codec: MessageCodec<T>,
		private readonly layers: Layers,
	) {}

	/**
	 * Begin an envelope over `codec` against an explicit {@link FrameCodec}.
	 * The `envelope()` entry point injects the shared wasm codec.
	 */
	static over<T>(
		frameCodec: FrameCodec,
		codec: MessageCodec<T>,
	): Envelope<T> {
		const begun = new Envelope(frameCodec, codec, {});
		return begun;
	}

	private with(patch: Partial<Layers>): Envelope<T> {
		const next = new Envelope(this.frameCodec, this.codec, {
			...this.layers,
			...patch,
		});
		return next;
	}

	/**
	 * Declare authenticity with the wrap-side capability: `frame()` signs
	 * with `signatory`, and `unwrap()` REQUIRES a valid signature.
	 *
	 * A profile `Secp256k1SigningKey` derives its own verifying key, so
	 * one call declares both directions. Any other {@link Signatory}
	 * (wallet, passkey, HSM) needs {@link verified} alongside it before
	 * `unwrap()` can check the signature.
	 */
	signed(signatory: Signatory): Envelope<T> {
		const next = this.with({ signer: signatory });
		return next;
	}

	/**
	 * Declare authenticity with the unwrap-side capability: `unwrap()`
	 * REQUIRES a signature verifying under `key` (the profile scheme).
	 * The read-only half of {@link signed}, for parties without the
	 * signing key.
	 */
	verified(key: Secp256k1VerifyingKey): Envelope<T> {
		const next = this.with({ verifier: key });
		return next;
	}

	/**
	 * Declare confidentiality: `frame()` seals the body, and `unwrap()`
	 * REJECTS a cleartext frame. `keys` contributes whichever halves it
	 * implements - `Aes256Gcm` both, an ECIES pair one each.
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
			patch = { ...patch, compressor: compression };
		}
		if ("decompress" in compression) {
			patch = { ...patch, inflator: compression };
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
			throw envelopeError(
				"ENVELOPE_SIGNER",
				"The envelope declares authenticity but has no signatory: " +
					"declare signed(signatory) to build frames",
			);
		}
		if (this.sealedDeclared() && this.layers.sealer === undefined) {
			throw envelopeError(
				"ENVELOPE_SEALER",
				"The envelope declares confidentiality but has no encryptor: " +
					"declare sealed(encryptor) to build frames",
			);
		}

		let builder = new FrameBuilder(this.frameCodec).withMessage(
			this.codec,
			message,
		);
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
	 * @throws ValidationError when a declared signature or seal is
	 * absent (downgrade), when a declared layer is missing its
	 * unwrap-side capability, or when the frame carries a layer the
	 * envelope cannot reverse.
	 * @throws when the signature does not verify, the opener rejects the
	 * ciphertext, the inflator rejects the body, or the codec rejects
	 * the decoded bytes.
	 */
	async unwrap(received: Frame): Promise<T> {
		this.checkAuthenticity(received);

		if (received.confidential) {
			const opener = this.layers.opener;
			if (opener === undefined) {
				throw envelopeError(
					"ENVELOPE_OPENER",
					"The frame is sealed but the envelope has no decryptor: " +
						"declare sealed(decryptor) to unwrap it",
				);
			}

			const opened = await received.decryptMessage(
				opener,
				this.codec,
				this.layers.inflator,
			);
			return opened;
		}

		if (this.sealedDeclared()) {
			throw envelopeError(
				"ENVELOPE_CLEARTEXT",
				"The envelope declares confidentiality but the frame body " +
					"is cleartext: refusing the downgrade",
			);
		}

		if (received.compressed) {
			const inflator = this.layers.inflator;
			if (inflator === undefined) {
				throw envelopeError(
					"ENVELOPE_INFLATOR",
					"The frame is compressed but the envelope has no " +
						"inflator: declare compressed(inflator) to unwrap it",
				);
			}

			const inflated = await received.inflateMessage(
				inflator,
				this.codec,
			);
			return inflated;
		}

		const message = received.message(this.codec);
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
		const declared =
			this.layers.signer !== undefined ||
			this.layers.verifier !== undefined;
		return declared;
	}

	/**
	 * Confidentiality is declared by either half.
	 */
	private sealedDeclared(): boolean {
		const declared =
			this.layers.sealer !== undefined ||
			this.layers.opener !== undefined;
		return declared;
	}

	/**
	 * The verifying key for `unwrap()`: the explicit declaration, or the
	 * one a profile signing key derives. Derived lazily so envelopes can
	 * compose before the wasm module initializes.
	 */
	private verifierKey(): Secp256k1VerifyingKey | undefined {
		if (this.layers.verifier !== undefined) {
			return this.layers.verifier;
		}

		const signer = this.layers.signer;
		if (signer instanceof Secp256k1SigningKey) {
			return signer.verifyingKey();
		}

		return undefined;
	}

	/**
	 * Enforce declared authenticity: the frame MUST carry a signature
	 * verifying under the declared (or derived) key.
	 */
	private checkAuthenticity(received: Frame): void {
		if (!this.authenticityDeclared()) {
			return;
		}

		const verifier = this.verifierKey();
		if (verifier === undefined) {
			throw envelopeError(
				"ENVELOPE_VERIFIER",
				"The envelope declares authenticity but its signatory " +
					"derives no verifying key: declare verified(key) to " +
					"unwrap frames",
			);
		}

		if (!received.signed) {
			throw envelopeError(
				"ENVELOPE_UNSIGNED",
				"The envelope declares authenticity but the frame is " +
					"unsigned: refusing the downgrade",
			);
		}

		received.verify(verifier);
	}
}
