/**
 * The boundary between the transport-agnostic builder and a concrete frame
 * assembler.
 *
 * A {@link FrameCodec} turns a validated {@link FrameSpec} into the DER bytes
 * of a tightbeam frame. The builder never assembles frames itself; it delegates
 * to whichever codec is injected, so the same fluent API drives a browser
 * WebAssembly backend or a possible Node backend.
 */

import type { FrameSpec } from "./spec.js";

/**
 * Assembles tightbeam frames from validated specifications.
 */
export interface FrameCodec {
	/**
	 * Assemble a complete frame from `spec`, returning the frame DER.
	 *
	 * The builder guarantees `spec` is structurally valid (body present,
	 * matrix dimensions consistent, version floors satisfied) before calling
	 * this method. A codec MAY still reject a spec it cannot honor.
	 */
	compose(spec: FrameSpec): Uint8Array;
}
