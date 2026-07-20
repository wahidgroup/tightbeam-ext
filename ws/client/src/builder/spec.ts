/**
 * The immutable frame specification accumulated by {@link FrameBuilder} and
 * consumed by a {@link FrameCodec}.
 */

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
	 * Row-major bytes; length MUST equal `n * n`.
	 */
	readonly data: Uint8Array;
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
	 * Explicit protocol version; when omitted the codec derives the floor.
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
	 * Monotonic order (Unix seconds).
	 */
	readonly order?: bigint;
	/**
	 * The opaque message body carried by the frame.
	 */
	readonly message?: Uint8Array;
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
	 * Body encryption (V1+): a symmetric cipher or an asymmetric encryptor
	 * to a recipient. The frame has a single body-encryption slot.
	 */
	readonly encryptor?: BodyEncryptor;
	/**
	 * Frame signatory (V1+).
	 */
	readonly signer?: Signatory;
}
