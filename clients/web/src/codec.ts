/**
 * WebAssembly-backed {@link FrameCodec}.
 */

import type { FrameCodec, FrameSpec } from "@wahidgroup/tightbeam-ts";
import { priorityOrdinal, versionOrdinal } from "@wahidgroup/tightbeam-ts";

import { FrameComposer } from "../wasm/tightbeam_ws_wasm.js";

const EMPTY_SALT = new Uint8Array();

/**
 * A {@link FrameCodec} that assembles frames via the wasm `FrameComposer`.
 */
export class WasmFrameCodec implements FrameCodec {
	compose(spec: FrameSpec): Uint8Array {
		const composer = new FrameComposer();

		if (spec.version !== undefined) {
			composer.withVersion(versionOrdinal(spec.version));
		}
		if (spec.id !== undefined) {
			composer.withId(spec.id);
		}
		if (spec.order !== undefined) {
			composer.withOrder(spec.order);
		}
		if (spec.message !== undefined) {
			composer.withMessage(spec.message);
		}
		if (spec.contentOid !== undefined) {
			composer.withContentOid(spec.contentOid);
		}
		if (spec.priority !== undefined) {
			composer.withPriority(priorityOrdinal(spec.priority));
		}
		if (spec.lifetimeSecs !== undefined) {
			composer.withLifetime(spec.lifetimeSecs);
		}
		if (spec.previousHash !== undefined) {
			composer.withPreviousHash(
				spec.previousHash.algorithmOid,
				spec.previousHash.digest,
			);
		}
		if (spec.matrix !== undefined) {
			composer.withMatrix(spec.matrix.n, spec.matrix.data);
		}
		if (spec.messageIntegrity !== undefined) {
			composer.withMessageHasher(
				spec.messageIntegrity.salt ?? EMPTY_SALT,
			);
		}
		if (spec.frameIntegrity === true) {
			composer.withWitnessHasher();
		}
		if (spec.signer !== undefined) {
			composer.withSigner(spec.signer.keyBytes);
		}

		return composer.build();
	}
}
