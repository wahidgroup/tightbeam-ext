/**
 * WebAssembly-backed {@link FrameCodec}.
 */

import {
	FrameComposer,
	attachSignature,
	attachWitness,
	bodyPreimage,
	commitmentPreimage,
	setConfidentiality,
	setMessageIntegrity,
	tbsBytes,
	witnessInput,
} from "#wasm";

import type { FrameCodec, FrameSpec } from "./builder/index.js";
import { effectiveVersion } from "./builder/index.js";

const EMPTY_SALT = new Uint8Array();

/**
 * A {@link FrameCodec} that assembles frames via the wasm structure engine.
 */
export class WasmFrameCodec implements FrameCodec {
	async compose(spec: FrameSpec): Promise<Uint8Array> {
		const bodyDer = bodyDerOf(spec);
		let der = composeStructural(spec, bodyDer);
		if (spec.messageIntegrity !== undefined) {
			const { hasher, salt } = spec.messageIntegrity;
			const digest = await hasher.digest(
				commitmentPreimage(salt ?? EMPTY_SALT, bodyDer),
			);

			der = setMessageIntegrity(der, hasher.algorithmOid, digest);
		}

		if (spec.encryptor !== undefined) {
			const sealed = await spec.encryptor.encrypt(bodyDer);
			der = setConfidentiality(
				der,
				spec.contentOid ?? spec.message?.contentOid,
				sealed.algorithmOid,
				sealed.parametersDer,
				sealed.ciphertext,
			);
		}
		if (spec.frameIntegrity !== undefined) {
			const digest = await spec.frameIntegrity.digest(witnessInput(der));
			der = attachWitness(der, spec.frameIntegrity.algorithmOid, digest);
		}
		if (spec.signer !== undefined) {
			const signature = await spec.signer.sign(tbsBytes(der));
			der = attachSignature(
				der,
				signature,
				spec.signer.signatureAlgorithmOid,
				spec.signer.digestAlgorithmOid,
				spec.signer.signerId(),
			);
		}

		return der;
	}
}

/**
 * The body DER installed in the frame, committed to by the hashers, and
 * sealed by the encryptor: the deferred message encoding, or the empty
 * profile body for a message-less spec.
 */
function bodyDerOf(spec: FrameSpec): Uint8Array {
	if (spec.message === undefined) {
		const bodyDer = bodyPreimage(new Uint8Array());
		return bodyDer;
	}

	const bodyDer = spec.message.encodeBody();
	return bodyDer;
}

/**
 * Assemble the structural frame: metadata only, version pinned to the
 * effective one (the wasm engine never sees the security fields, so the
 * TypeScript floor is authoritative).
 */
function composeStructural(spec: FrameSpec, bodyDer: Uint8Array): Uint8Array {
	const composer = new FrameComposer();
	composer.withVersion(effectiveVersion(spec));
	composer.withMessage(bodyDer);

	if (spec.id !== undefined) {
		composer.withId(spec.id);
	}
	if (spec.order !== undefined) {
		composer.withOrder(spec.order);
	}
	if (spec.priority !== undefined) {
		composer.withPriority(spec.priority);
	}
	if (spec.lifetime !== undefined) {
		composer.withLifetime(spec.lifetime);
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

	const der = composer.build();
	return der;
}
