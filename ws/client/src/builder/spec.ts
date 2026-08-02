/**
 * The immutable frame specification accumulated by {@link FrameBuilder} and
 * consumed by a {@link FrameCodec}.
 */

import type { BodyCompressor } from "../compress.js";
import type { BodyEncryptor, Hasher, Signatory } from "../crypto.js";
import type { MessagePriority } from "./priority.js";
import type { Version } from "./version.js";

/**
 * A link to a parent frame by the digest of its content (V2+).
 */
export interface PreviousHashSpec {
	/**
	 * Dotted OID of the digest algorithm (e.g. SHA3-256).
	 */
	readonly algorithmOid: string;
	/**
	 * The raw digest octets produced by `algorithmOid`.
	 */
	readonly digest: Uint8Array;
}

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
 * assembly, so builders stay usable before the wasm module initializes and
 * the codec's type parameter never leaks into the spec.
 */
export interface MessageSlot {
	/**
	 * Content-type OID declared by the codec, recorded when the body is
	 * sealed (an explicit `withContentOid` takes precedence).
	 */
	readonly contentOid?: string;

	/**
	 * Produce the body DER installed in the frame.
	 */
	encodeBody(): Uint8Array;
}

/**
 * Message-body integrity (V2+): commits to the body under the caller's
 * hasher.
 */
export interface MessageIntegritySpec {
	/**
	 * The commitment hasher.
	 */
	readonly hasher: Hasher;
	/**
	 * Optional salt mixed into the message digest.
	 */
	readonly salt?: Uint8Array;
}

/**
 * The complete, immutable description of a frame to assemble.
 */
export interface FrameSpec {
	/**
	 * Explicit protocol version. When omitted, the codec derives the floor.
	 */
	readonly version?: Version;
	/**
	 * Version equality assertion: build fails when the effective version
	 * differs.
	 */
	readonly assertedVersion?: Version;
	/**
	 * Opaque message identifier.
	 */
	readonly id?: Uint8Array;
	/**
	 * Frame order stamp.
	 *
	 * The value is protocol-opaque. Any monotonic scheme works, such as a
	 * Unix timestamp or a dense per-channel counter. When omitted, the
	 * build defaults it to the current Unix time in seconds.
	 */
	readonly order?: bigint;
	/**
	 * The frame body: a deferred encoding of the caller's message.
	 */
	readonly message?: MessageSlot;
	/**
	 * Dotted OID describing the body content type.
	 */
	readonly contentOid?: string;
	/**
	 * Message priority (V2+).
	 */
	readonly priority?: MessagePriority;
	/**
	 * Time-to-live in seconds (V2+).
	 */
	readonly lifetime?: bigint;
	/**
	 * Parent-frame link by content digest (V2+).
	 */
	readonly previousHash?: PreviousHashSpec;
	/**
	 * N×N control matrix (V3+).
	 */
	readonly matrix?: MatrixSpec;
	/**
	 * Message-body integrity commitment (V2+).
	 */
	readonly messageIntegrity?: MessageIntegritySpec;
	/**
	 * Witness the envelope with frame integrity under this hasher (V2+).
	 */
	readonly frameIntegrity?: Hasher;
	/**
	 * Body compression (any version): applied after the message commitment
	 * and before encryption.
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
