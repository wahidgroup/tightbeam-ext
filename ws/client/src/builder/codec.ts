/**
 * The boundary between the transport-agnostic builder and a concrete frame
 * assembler.
 *
 * A {@link FrameCodec} turns a validated {@link FrameSpec} into the DER bytes
 * of a tightbeam frame, driving the spec's cryptographic capabilities
 * (hashers, encryptor, signatory) through the assembly pipeline.
 */

import type { FrameSpec } from "./spec.js";

/**
 * Assembles tightbeam frames from validated specifications.
 */
export interface FrameCodec {
	/**
	 * Assemble a complete frame from `spec`, resolving with the frame DER.
	 *
	 * The builder guarantees `spec` is structurally valid before calling
	 * this method. A codec MAY still reject a spec it cannot honor.
	 */
	compose(spec: FrameSpec): Promise<Uint8Array>;
}
