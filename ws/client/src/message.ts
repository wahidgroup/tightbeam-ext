/**
 * Typed message bodies, as the typed messages section of `docs/ws-client.md`
 * describes.
 */

import type { Oid, OpaqueCodec } from "#wasm";

import type { OidName } from "./views.js";
import { ClientTransportError } from "./errors.js";
import { Owned } from "./owned.js";
import { OidView } from "./views.js";

/**
 * A typed view over the frame body DER: the implementor's serialization
 * contract with the peer, including runtime validation on decode.
 */
export interface MessageCodec<T> {
	/**
	 * Optional content type recorded in the confidentiality info when the
	 * body is sealed.
	 */
	readonly contentOid?: OidName;

	/**
	 * Encode `message` as the body DER installed in the frame.
	 *
	 * @throws any error of the implementation, which rejects the build.
	 */
	readonly encode: (message: T) => Uint8Array;

	/**
	 * Decode and runtime-validate a body DER.
	 *
	 * @throws when the bytes do not satisfy the schema.
	 */
	readonly decode: (bodyDer: Uint8Array) => T;
}

/**
 * A payload-level codec: serialization of `T` to raw bytes, without any
 * ASN.1 concern. Lift one into a {@link MessageCodec} with
 * `Engine.wrapping`.
 */
export interface PayloadCodec<T> {
	/**
	 * Optional content type recorded in the confidentiality info when the
	 * body is sealed.
	 */
	readonly contentOid?: OidName;

	/**
	 * Serialize `message` to payload bytes.
	 *
	 * @throws any error of the implementation, which rejects the build.
	 */
	readonly encode: (message: T) => Uint8Array;

	/**
	 * Parse and runtime-validate payload bytes.
	 *
	 * @throws when the bytes do not satisfy the schema.
	 */
	readonly decode: (payload: Uint8Array) => T;
}

/**
 * The copy of the content type that a held codec owns, and the view of it
 * that the codec lends.
 */
interface HeldContentOid {
	readonly hold: Owned<Oid>;
	readonly view: OidView;
}

/**
 * A codec held past the call that received it: the caller's codec, under a
 * copy of the content type it declares, lent as a view. A holder with a
 * release frees the copy as it disposes the codec, and the glue reclaims the
 * copy of any other holder with that holder.
 */
export class HeldCodec<T> implements MessageCodec<T>, Disposable {
	readonly #codec: MessageCodec<T>;

	/**
	 * The hold of the copy of the declared content type, which the disposal
	 * ends, and the view that reads through it, or `undefined` for a codec
	 * that declares none.
	 */
	readonly #copy: HeldContentOid | undefined;

	private constructor(codec: MessageCodec<T>) {
		this.#codec = codec;

		const declared = codec.contentOid;
		if (declared !== undefined) {
			const copy = declared.clone();
			const hold = new Owned(copy, ClientTransportError.codecReleased);
			const view = OidView.held(hold);
			this.#copy = { hold, view };
		}
	}

	/**
	 * `codec`, held under a copy of the content type it declares.
	 */
	static of<T>(codec: MessageCodec<T>): HeldCodec<T> {
		const held = new HeldCodec(codec);
		return held;
	}

	/**
	 * The copy of the content type the codec declares, lent as a view that
	 * reads through the hold, or `undefined` for a codec that declares none.
	 *
	 * @throws TightbeamTransportError `CodecReleased` from this read, or from a
	 * read of the view, once the holder disposed the codec.
	 */
	get contentOid(): OidView | undefined {
		const copy = this.#copy;
		if (copy === undefined) {
			return undefined;
		}

		copy.hold.use("contentOid");
		return copy.view;
	}

	encode(message: T): Uint8Array {
		const bodyDer = this.#codec.encode(message);
		return bodyDer;
	}

	decode(bodyDer: Uint8Array): T {
		const message = this.#codec.decode(bodyDer);
		return message;
	}

	/**
	 * Free the copy. The disposal is idempotent, and a later read of {@link contentOid} refuses with `CodecReleased`.
	 */
	[Symbol.dispose](): void {
		this.#copy?.hold[Symbol.dispose]();
	}
}

/**
 * The codecs over the profile opaque body (`SEQUENCE { OCTET STRING }`), bound
 * to the `OpaqueCodec` of one loaded module.
 */
export class Codecs {
	readonly #opaqueBody: typeof OpaqueCodec;

	private constructor(opaqueBody: typeof OpaqueCodec) {
		this.#opaqueBody = opaqueBody;
	}

	/**
	 * The codecs over the `OpaqueCodec` of `glue`, the loaded module.
	 */
	static over(glue: { readonly OpaqueCodec: typeof OpaqueCodec }): Codecs {
		const codecs = new Codecs(glue.OpaqueCodec);
		return codecs;
	}

	/**
	 * The profile codec: raw bytes in the opaque body wrapper.
	 * `Engine.frameBuilder(bytes)` is sugar over it.
	 */
	get opaque(): MessageCodec<Uint8Array> {
		const opaque = this.wrapping({
			encode: (bytes: Uint8Array): Uint8Array => bytes,
			decode: (payload: Uint8Array): Uint8Array => payload,
		});
		return opaque;
	}

	/**
	 * Lift a payload codec into a {@link MessageCodec} that wraps its bytes in
	 * the profile opaque body, so the encoded body stays valid ASN.1 and the
	 * payload codec writes no DER.
	 */
	wrapping<T>(inner: PayloadCodec<T>): MessageCodec<T> {
		const opaqueBody = this.#opaqueBody;
		const codec = {
			contentOid: inner.contentOid,
			encode(message: T): Uint8Array {
				const payload = inner.encode(message);
				const bodyDer = opaqueBody.encode(payload);
				return bodyDer;
			},
			decode(bodyDer: Uint8Array): T {
				const payload = opaqueBody.decode(bodyDer);
				const message = inner.decode(payload);
				return message;
			},
		};
		return codec;
	}
}
