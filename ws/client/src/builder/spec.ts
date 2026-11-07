/**
 * The immutable frame specification accumulated by {@link FrameBuilder}.
 * A salt, an OID, or a digest arrives in it already parsed by the engine, so
 * the build never meets a malformed one.
 */

import type { MessagePriority, Version } from "#wasm";

import type { BodyCompressor } from "../compress.js";
import type { BodyEncryptor, Hasher, Signatory } from "../crypto.js";
import type { DigestInfoView, OidView } from "../views.js";

/**
 * An N×N control matrix (V3+), stored row-major as exactly `n * n` octets.
 */
export interface MatrixSpec {
	/**
	 * Dimension N, in `1..=255`.
	 */
	readonly n: number;
	/**
	 * Row-major bytes. Length MUST equal `n * n`.
	 */
	readonly data: Uint8Array;
}

/**
 * The frame body captured by `withMessage`: encoding is deferred to
 * assembly, so the codec's type parameter never leaks into the spec.
 */
export interface MessageSlot {
	/**
	 * Content type declared by the codec, recorded when the body is sealed
	 * (an explicit `withContentOid` takes precedence).
	 */
	readonly contentOid?: OidView;

	/**
	 * Produce the body DER installed in the frame.
	 */
	encodeBody(): Uint8Array;
}

/**
 * The complete, immutable description of a frame to assemble.
 */
export interface FrameSpec {
	/**
	 * Explicit protocol version. When omitted, the engine derives the floor.
	 */
	readonly version?: Version;
	/**
	 * Version equality assertion: build fails when the built frame carries
	 * another version.
	 */
	readonly assertedVersion?: Version;
	/**
	 * Opaque message identifier.
	 */
	readonly id?: Uint8Array;
	/**
	 * Frame order stamp, which the engine parses at the build.
	 *
	 * The value is protocol-opaque. Any monotonic scheme works, such as a
	 * Unix timestamp or a dense per-channel counter. When omitted, the
	 * build defaults it to the current Unix time in seconds.
	 */
	readonly order?: bigint | number;
	/**
	 * The frame body: a deferred encoding of the caller's message.
	 */
	readonly message?: MessageSlot;
	/**
	 * OID describing the body content type.
	 */
	readonly contentOid?: OidView;
	/**
	 * Message priority (V2+).
	 */
	readonly priority?: MessagePriority;
	/**
	 * Time-to-live in seconds (V2+), which the engine parses at the build.
	 */
	readonly lifetime?: bigint | number;
	/**
	 * Parent-frame link by content digest (V2+).
	 */
	readonly previousHash?: DigestInfoView;
	/**
	 * N×N control matrix (V3+).
	 */
	readonly matrix?: MatrixSpec;
	/**
	 * Commit to the message body under this hasher (V1+): the caller's digest,
	 * under the copy of its algorithm that the builder holds.
	 */
	readonly messageIntegrity?: Hasher;
	/**
	 * Witness the envelope with frame integrity under this hasher (V1+), held
	 * as {@link messageIntegrity} is.
	 */
	readonly frameIntegrity?: Hasher;
	/**
	 * Body compression (any version): applied after the message commitment
	 * and before encryption. The caller's compression, under the copy of its
	 * algorithm that the builder holds.
	 */
	readonly compressor?: BodyCompressor;
	/**
	 * Body encryption (V1+): a symmetric cipher or an asymmetric encryptor
	 * to a recipient. The frame has a single body-encryption slot.
	 */
	readonly encryptor?: BodyEncryptor;
	/**
	 * Frame signatory (V1+).
	 */
	readonly signer?: Signatory;
}
