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
const EMPTY_MESSAGE = new Uint8Array();

/**
 * A {@link FrameCodec} that assembles frames via the wasm structure engine.
 */
export class WasmFrameCodec implements FrameCodec {
	async compose(spec: FrameSpec): Promise<Uint8Array> {
		let der = composeStructural(spec);
		if (spec.messageIntegrity !== undefined) {
			const { hasher, salt } = spec.messageIntegrity;
			const digest = await hasher.digest(
				commitmentPreimage(salt ?? EMPTY_SALT, bodyDerOf(spec)),
			);

			der = setMessageIntegrity(der, hasher.algorithmOid, digest);
		}

		if (spec.encryptor !== undefined) {
			const sealed = await spec.encryptor.encrypt(bodyDerOf(spec));
			der = setConfidentiality(
				der,
				spec.contentOid,
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
 * The body DER the hashers commit to and the encryptor seals.
 */
function bodyDerOf(spec: FrameSpec): Uint8Array {
	return bodyPreimage(spec.message ?? EMPTY_MESSAGE);
}

/**
 * Assemble the structural frame: metadata only, version pinned to the
 * effective one (the wasm engine never sees the security fields, so the
 * TypeScript floor is authoritative).
 */
function composeStructural(spec: FrameSpec): Uint8Array {
	const composer = new FrameComposer();
	composer.withVersion(effectiveVersion(spec));

	if (spec.id !== undefined) {
		composer.withId(spec.id);
	}
	if (spec.order !== undefined) {
		composer.withOrder(spec.order);
	}
	if (spec.message !== undefined) {
		composer.withMessage(spec.message);
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

	return composer.build();
}
