/**
 * The codec that the client unit tests and the node suite of `pubsub/tests` share.
 */

import type { Engine, MessageCodec, OidName } from "@wahidgroup/tightbeam-ws-client";

/**
 * A content type a codec names, as the dotted form of an object identifier.
 */
export const CONTENT_TYPE = "1.2.840.113549.1.7.1";

/**
 * The profile opaque codec of `engine` under the content type `contentOid`.
 */
export function codecNaming(engine: Engine, contentOid: OidName): MessageCodec<Uint8Array> {
	const codec = engine.wrapping({
		contentOid,
		encode: (message: Uint8Array): Uint8Array => message,
		decode: (payload: Uint8Array): Uint8Array => payload,
	});
	return codec;
}
