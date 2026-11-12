/**
 * Detached, hiding message commitments (`tightbeam::crypto::commitment`), as
 * the detached commitments section of `docs/ws-client.md` describes.
 */

import type { CommitmentSalt, DigestInfo } from "#wasm";

import type { Hasher } from "./crypto.js";
import type { EngineParts } from "./engine.js";
import type { DigestName } from "./views.js";
import { ClientTransportError } from "./errors.js";
import { Owned } from "./owned.js";

/**
 * The opening of a message commitment: the secret blinding salt and the
 * committed body DER. A disclosed opening lets any holder of the commitment
 * verify it through {@link Opening.verify}. The opening owns the salt it took,
 * and its disposal frees it.
 */
export class Opening implements Disposable {
	readonly #parts: EngineParts;

	readonly #salt: Owned<CommitmentSalt>;

	readonly #bodyDer: Uint8Array;

	private constructor(parts: EngineParts, salt: CommitmentSalt, bodyDer: Uint8Array) {
		this.#parts = parts;
		this.#salt = new Owned(salt, ClientTransportError.openingReleased);
		this.#bodyDer = bodyDer;
	}

	/**
	 * The opening of `bodyDer` under `salt`, through the engine `parts`. It copies `bodyDer` and then takes the salt,
	 * so a refused copy leaves the caller its salt, and an opening leaves the caller an empty shell.
	 *
	 * @throws TightbeamTransportError `CommitmentSpent` when the salt moved out of `salt` already.
	 *
	 * @internal
	 */
	static over(parts: EngineParts, salt: CommitmentSalt, bodyDer: Uint8Array): Opening {
		const body = new Uint8Array(bodyDer);
		const taken = salt.take();

		const opening = new Opening(parts, taken, body);
		return opening;
	}

	/**
	 * The public commitment of this opening under `hasher`: the digest to
	 * publish, which a high-entropy salt makes hiding.
	 *
	 * @throws an error whose `code` is `SerializationError` when the body is
	 * not one DER value, and `OpeningReleased` after the disposal.
	 */
	async commit(hasher: Hasher): Promise<DigestInfo> {
		const salt = this.#salt.use("commit");
		const preimage = salt.preimage(this.#bodyDer);
		const digest = await hasher.digest(preimage);

		using algorithmOid = hasher.algorithmOid.clone();

		const commitment = this.#parts.glue.DigestInfo.of(algorithmOid, digest);
		return commitment;
	}

	/**
	 * Verify this opening against `commitment` in constant time, and resolve
	 * with `false` on an algorithm or a digest mismatch.
	 *
	 * @throws an error whose `code` is `SerializationError` when the disclosed
	 * body is not one DER value, and `OpeningReleased` after the disposal.
	 */
	async verify(hasher: Hasher, commitment: DigestName): Promise<boolean> {
		const salt = this.#salt.use("verify");
		const preimage = salt.preimage(this.#bodyDer);
		const recomputed = await hasher.digest(preimage);

		using carried = commitment.clone();
		using algorithmOid = hasher.algorithmOid.clone();

		const verdict = carried.verdict(algorithmOid, recomputed);
		const verified = verdict === "verified";
		return verified;
	}

	/**
	 * A copy of the committed body DER, so a write to it leaves this opening
	 * unchanged.
	 */
	get bodyDer(): Uint8Array {
		const bodyDer = new Uint8Array(this.#bodyDer);
		return bodyDer;
	}

	/**
	 * Free the salt this opening took. The release is idempotent, and a later `commit` or `verify` refuses with
	 * `OpeningReleased`.
	 */
	[Symbol.dispose](): void {
		this.#salt[Symbol.dispose]();
	}
}
