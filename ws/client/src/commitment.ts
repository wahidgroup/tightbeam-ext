/**
 * Detached, hiding message commitments (`tightbeam::crypto::commitment`).
 *
 * A bare `H(body)` digest binds but does not hide: a brute force over
 * candidate preimages recovers a low-entropy body from a published digest. A
 * commitment salts the body with a secret blinding value, so the digest
 * reveals nothing until the opening `(salt, body)` is disclosed.
 *
 * - The commitment covers the same mode-prefixed preimage as the in-frame
 *   message commitment, so a detached commitment and a frame-carried one are
 *   interchangeable.
 * - The engine parses the salt (`Engine.salt`): empty commits in plain-digest
 *   mode, and any other salt carries at least 16 octets.
 */

import type { CommitmentSalt, DigestInfo, DigestVerdict, Oid } from "#wasm";

import type { Hasher } from "./crypto.js";
import type { EngineParts } from "./engine.js";
import type { DigestName } from "./views.js";
import { Lent } from "./views.js";
import { ClientTransportError } from "./errors.js";
import { Owned } from "./owned.js";

/**
 * The opening of a message commitment: the secret blinding salt and the
 * committed body DER.
 *
 * Disclosing an `Opening` lets any holder of the commitment verify it via
 * {@link Opening.verify}, realizing a disclose-then-verify proof. The opening
 * owns the salt it took, and its disposal frees it.
 */
export class Opening implements Disposable {
	readonly #parts: EngineParts;

	readonly #salt: Owned<CommitmentSalt>;

	readonly #bodyDer: Uint8Array;

	private constructor(
		parts: EngineParts,
		salt: CommitmentSalt,
		bodyDer: Uint8Array,
	) {
		this.#parts = parts;
		this.#salt = new Owned(salt, ClientTransportError.openingReleased);
		this.#bodyDer = bodyDer;
	}

	/**
	 * The opening of `bodyDer` under `salt`, through the engine `parts`. The
	 * opening takes the salt and keeps its own copy of `bodyDer`, so the
	 * caller's salt keeps an empty shell and a later write to `bodyDer` leaves
	 * the opening as it was made.
	 *
	 * @throws TightbeamTransportError `CommitmentSpent` when the salt moved
	 * out of `salt` already.
	 */
	static over(
		parts: EngineParts,
		salt: CommitmentSalt,
		bodyDer: Uint8Array,
	): Opening {
		const taken = salt.take();
		const body = new Uint8Array(bodyDer);

		const opening = new Opening(parts, taken, body);
		return opening;
	}

	/**
	 * The public commitment of this opening under `hasher`: the digest to
	 * publish. A high-entropy salt of at least 16 octets makes it hiding, and
	 * an empty salt commits in plain-digest mode (binding only).
	 *
	 * @throws an error whose `code` is `SerializationError` when the body is
	 * not one DER value, and `OpeningReleased` after the disposal.
	 */
	async commit(hasher: Hasher): Promise<DigestInfo> {
		const salt = this.#salt.use("commit");
		const preimage = salt.preimage(this.#bodyDer);
		const digest = await hasher.digest(preimage);

		const digests = this.#parts.glue.DigestInfo;
		const of = (algorithmOid: Oid): DigestInfo =>
			digests.of(algorithmOid, digest);
		const commitment = Lent.oid(hasher.algorithmOid, of);
		return commitment;
	}

	/**
	 * Verify this opening against `commitment` in constant time.
	 *
	 * Resolves with `false` when the commitment algorithm does not match
	 * `hasher` or when the recomputed digest differs.
	 *
	 * @throws an error whose `code` is `SerializationError` when the disclosed
	 * body is not one DER value, and `OpeningReleased` after the disposal.
	 */
	async verify(hasher: Hasher, commitment: DigestName): Promise<boolean> {
		const salt = this.#salt.use("verify");
		const preimage = salt.preimage(this.#bodyDer);
		const recomputed = await hasher.digest(preimage);

		const judge = (digest: DigestInfo): DigestVerdict => {
			const compare = (algorithmOid: Oid): DigestVerdict =>
				digest.verdict(algorithmOid, recomputed);
			return Lent.oid(hasher.algorithmOid, compare);
		};

		const verdict = Lent.digest(commitment, judge);
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
	 * Free the salt this opening took. A later release does nothing, and a
	 * later `commit` or `verify` refuses with `OpeningReleased`.
	 */
	[Symbol.dispose](): void {
		this.#salt[Symbol.dispose]();
	}
}
