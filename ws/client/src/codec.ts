/**
 * WebAssembly-backed {@link FrameCodec}.
 */

import {
	FrameComposer,
	attachSignature,
	attachWitness,
	bodyPreimage,
	commitmentPreimage,
	setCompactness,
	setConfidentiality,
	setMessageIntegrity,
	signingPrehash,
	witnessInput,
} from "#wasm";

import type { FrameCodec, FrameSpec } from "./builder/index.js";
import { ValidationError, effectiveVersion } from "./builder/index.js";
import type { Signatory } from "./crypto.js";
import { PROFILE_OIDS } from "./crypto.js";

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

		// The bytes the encryptor seals: the compressed body when a
		// compressor is configured (peers decompress after decrypting).
		let sealInput = bodyDer;
		if (spec.compressor !== undefined) {
			const compressed = await spec.compressor.compress(bodyDer);
			der = setCompactness(
				der,
				compressed.contentOid,
				compressed.algorithmOid,
				compressed.parametersDer,
				compressed.data,
			);
			sealInput = compressed.data;
		}

		if (spec.encryptor !== undefined) {
			const contentOid = spec.contentOid ?? spec.message?.contentOid;
			const sealed = await spec.encryptor.encrypt(sealInput, contentOid);
			der = setConfidentiality(
				der,
				sealed.envelopeDer,
				sealed.ciphertext,
			);
		}
		if (spec.frameIntegrity !== undefined) {
			const digest = await spec.frameIntegrity.digest(witnessInput(der));
			der = attachWitness(der, spec.frameIntegrity.algorithmOid, digest);
		}
		if (spec.signer !== undefined) {
			requireProfileSigner(spec.signer);

			const signerId = spec.signer.signerId();
			const signature = await spec.signer.signPrehash(
				signingPrehash(der, signerId),
			);
			der = attachSignature(der, signature, signerId);
		}

		return der;
	}
}

/**
 * Reject a signer outside the profile signature, the one form the wasm
 * engine's CMS `SignerInfo` carries.
 */
function requireProfileSigner(signer: Signatory): void {
	if (
		signer.signatureAlgorithmOid !== PROFILE_OIDS.ecdsaWithSha3_256 ||
		signer.digestAlgorithmOid !== PROFILE_OIDS.sha3_256
	) {
		throw new ValidationError("ALGORITHM_MISMATCH", [
			{
				path: "signer.signatureAlgorithmOid",
				message: `Signs with ${signer.signatureAlgorithmOid}, but a frame carries ${PROFILE_OIDS.ecdsaWithSha3_256}`,
			},
		]);
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
