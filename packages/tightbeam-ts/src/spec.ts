/**
 * The immutable frame specification accumulated by {@link FrameBuilder} and
 * consumed by a {@link FrameCodec}.
 */

import type { FrameVersion } from "./version.js";
import type { MessagePriority } from "./priority.js";

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
 * An N×N control matrix (V2+), stored row-major as exactly `n * n` octets.
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
 * Message-body integrity (V2+): commits to the body with SHA3-256.
 */
export interface MessageIntegritySpec {
	/**
	 * Optional salt mixed into the message digest.
	 */
	readonly salt?: Uint8Array;
}

/**
 * The signature scheme selectors supported for local (in-process) signing.
 */
export type LocalSignerScheme = "secp256k1";

/**
 * A local signer: the private key is held in process and the frame is signed
 * during assembly. External signers (wallet/passkey/HSM) are handled by the
 * detached-signing API and are not part of this spec.
 */
export interface LocalSignerSpec {
	readonly scheme: LocalSignerScheme;
	/**
	 * Raw private-key bytes for `scheme`.
	 */
	readonly keyBytes: Uint8Array;
}

/**
 * The complete, immutable description of a frame to assemble.
 */
export interface FrameSpec {
	/**
	 * Explicit protocol version; when omitted the codec derives the floor.
	 */
	readonly version?: FrameVersion;
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
	readonly lifetimeSecs?: bigint;
	/**
	 * Parent-frame link by content digest (V2+).
	 */
	readonly previousHash?: PreviousHashSpec;
	/**
	 * N×N control matrix (V2+).
	 */
	readonly matrix?: MatrixSpec;
	/**
	 * Message-body integrity commitment (V2+).
	 */
	readonly messageIntegrity?: MessageIntegritySpec;
	/**
	 * Whether to witness the envelope with frame integrity (V2+).
	 */
	readonly frameIntegrity?: boolean;
	/**
	 * Local (in-process) signer (V1+).
	 */
	readonly signer?: LocalSignerSpec;
}
