/**
 * Detached, hiding message commitments (`tightbeam::crypto::commitment`).
 *
 * A bare `H(body)` digest is binding but not hiding: a low-entropy body can
 * be recovered by brute-forcing candidate preimages against a published
 * digest. A commitment salts the body with a secret blinding value so the
 * digest reveals nothing until the opening `(salt, body)` is disclosed.
 *
 * The commitment value is computed over the same length-framed preimage the
 * in-frame message commitment uses (`commitmentPreimage`), so a detached
 * commitment and a frame-carried one are interchangeable. An empty salt
 * reproduces the plain body digest.
 */

import { commitmentPreimage } from "#wasm";

import type { Hasher } from "./crypto.js";
import type { DigestInfo } from "./frame.js";

/**
 * The result of {@link Opening.prove}: the public commitment to publish and
 * the secret opening to disclose during verification.
 */
export interface ProvenCommitment {
	/**
	 * The public commitment digest.
	 */
	readonly commitment: DigestInfo;

	/**
	 * The secret proof: disclose it to let a commitment holder verify.
	 */
	readonly opening: Opening;
}

/**
 * Constant-time byte-slice equality.
 */
function constantTimeEqual(lhs: Uint8Array, rhs: Uint8Array): boolean {
	if (lhs.length !== rhs.length) {
		return false;
	}

	let difference = 0;
	for (let index = 0; index < lhs.length; index += 1) {
		const left = lhs[index] ?? 0;
		const right = rhs[index] ?? 0;
		difference |= left ^ right;
	}

	return difference === 0;
}

/**
 * The opening of a message commitment: the secret blinding salt and the
 * committed body DER.
 *
 * Disclosing an `Opening` lets any holder of the commitment verify it via
 * {@link Opening.verify}, realizing a disclose-then-verify proof.
 */
export class Opening {
	private constructor(
		private readonly saltBytes: Uint8Array,
		private readonly bodyBytes: Uint8Array,
	) {}

	/**
	 * Produce a commitment over `bodyDer` together with its opening.
	 *
	 * The returned commitment is the public value to publish. The opening
	 * is the secret proof to disclose during verification. A high-entropy
	 * `salt` makes the commitment hiding. An empty salt yields the plain
	 * body digest (binding only).
	 */
	static async prove(
		hasher: Hasher,
		bodyDer: Uint8Array,
		salt: Uint8Array,
	): Promise<ProvenCommitment> {
		const preimage = commitmentPreimage(salt, bodyDer);
		const digest = await hasher.digest(preimage);

		const commitment = { algorithmOid: hasher.algorithmOid, digest };
		const opening = new Opening(salt, bodyDer);
		return { commitment, opening };
	}

	/**
	 * Reassemble a disclosed opening from its parts, on the verifying side.
	 */
	static fromParts(salt: Uint8Array, bodyDer: Uint8Array): Opening {
		const opening = new Opening(salt, bodyDer);
		return opening;
	}

	/**
	 * Verify this opening against a commitment in constant time.
	 *
	 * Resolves with `false` when the commitment algorithm does not match
	 * `hasher` or when the recomputed digest differs.
	 */
	async verify(hasher: Hasher, commitment: DigestInfo): Promise<boolean> {
		if (commitment.algorithmOid !== hasher.algorithmOid) {
			return false;
		}

		const preimage = commitmentPreimage(this.saltBytes, this.bodyBytes);
		const recomputed = await hasher.digest(preimage);

		const verified = constantTimeEqual(recomputed, commitment.digest);
		return verified;
	}

	/**
	 * The blinding salt.
	 */
	get salt(): Uint8Array {
		return this.saltBytes;
	}

	/**
	 * The committed body DER.
	 */
	get bodyDer(): Uint8Array {
		return this.bodyBytes;
	}
}
