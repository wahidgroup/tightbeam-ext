/**
 * Typed message bodies.
 *
 * The protocol treats the frame body as opaque DER: what it encodes is the
 * implementor's contract with the peer. A {@link MessageCodec} pairs a
 * TypeScript type with that contract - `encode` produces the body DER,
 * `decode` parses and runtime-validates it.
 *
 * Two styles:
 *
 * - **Wrapped payload** ({@link wrapped}): serialize `T` to bytes however
 *   you like (JSON, CBOR, protobuf) and let the library wrap them in the
 *   profile opaque body.
 * - **Full DER**: implement {@link MessageCodec} directly with an ASN.1
 *   library to match a peer's typed `Message` schema.
 */

import { bodyPreimage, decodeBody } from "#wasm";

/**
 * A typed view over the frame body DER: the implementor's serialization
 * contract with the peer, including runtime validation on decode.
 */
export interface MessageCodec<T> {
	/**
	 * Optional content-type OID recorded in the confidentiality info when
	 * the body is sealed.
	 */
	readonly contentOid?: string;

	/**
	 * Encode `message` as the body DER installed in the frame.
	 */
	encode(message: T): Uint8Array;

	/**
	 * Decode and runtime-validate a body DER.
	 *
	 * @throws when the bytes do not satisfy the schema.
	 */
	decode(bodyDer: Uint8Array): T;
}

/**
 * A payload-level codec: serialization of `T` to raw bytes, without any
 * ASN.1 concern. Lift one into a {@link MessageCodec} with {@link wrapped}.
 */
export interface PayloadCodec<T> {
	/**
	 * Optional content-type OID recorded in the confidentiality info when
	 * the body is sealed.
	 */
	readonly contentOid?: string;

	/**
	 * Serialize `message` to payload bytes.
	 */
	encode(message: T): Uint8Array;

	/**
	 * Parse and runtime-validate payload bytes.
	 *
	 * @throws when the bytes do not satisfy the schema.
	 */
	decode(payload: Uint8Array): T;
}

/**
 * Lift a payload-level codec into a {@link MessageCodec} by wrapping its
 * bytes in the profile opaque body (`SEQUENCE { OCTET STRING }`), the way
 * `frame(bytes)` does. The wire stays valid ASN.1 without the implementor
 * touching DER.
 *
 * The wasm module MUST be initialized (`initClient`) before the returned
 * codec encodes or decodes.
 */
export function wrapped<T>(inner: PayloadCodec<T>): MessageCodec<T> {
	const codec = {
		contentOid: inner.contentOid,
		encode(message: T): Uint8Array {
			const payload = inner.encode(message);
			const bodyDer = bodyPreimage(payload);
			return bodyDer;
		},
		decode(bodyDer: Uint8Array): T {
			const payload = decodeBody(bodyDer);
			const message = inner.decode(payload);
			return message;
		},
	};
	return codec;
}

/**
 * The profile codec: raw bytes in the opaque body wrapper. `frame(bytes)`
 * and `withMessage(bytes)` are sugar over it.
 */
export const Opaque: MessageCodec<Uint8Array> = wrapped({
	encode(bytes: Uint8Array): Uint8Array {
		return bytes;
	},
	decode(payload: Uint8Array): Uint8Array {
		return payload;
	},
});
