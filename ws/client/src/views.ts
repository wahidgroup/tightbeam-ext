/**
 * Views of wasm handles that another holder owns.
 *
 * Every wasm handle that TypeScript code keeps past the call that received it
 * is a copy the holder owns, a handle the holder took, a hold through
 * `Owned` with a coded refusal, or a handle another holder owns, lent through
 * a view. A view has no `free` and no `[Symbol.dispose]`, so no caller can
 * release the handle under its owner. The owner is the engine of the realm,
 * or the frame that decoded the handle.
 */

import type { DigestInfo, DigestVerdict, Oid, ProfileOids } from "#wasm";

import type { Owned } from "./owned.js";

/**
 * An object identifier as a caller names one: an `Oid` the caller owns, or a
 * view of one that another holder owns. A holder that keeps it past the call
 * keeps a `clone()` of its own.
 */
export type OidName = Pick<Oid, "clone" | "toString">;

/**
 * A digest as a caller names one: a `DigestInfo` the caller owns, or a view
 * of one that a frame owns. A holder that keeps it past the call keeps a
 * `clone()` of its own.
 */
export type DigestName = Pick<DigestInfo, "clone">;

/**
 * The handle that a read of a view reaches, for `operation`.
 */
type OidRead = (operation: string) => Oid;

/**
 * An object identifier that another holder owns, lent with no release.
 */
export class OidView implements OidName {
	readonly #oid: OidRead;

	private constructor(oid: OidRead) {
		this.#oid = oid;
	}

	/**
	 * A view of `oid`, which the caller keeps owning.
	 */
	static over(oid: Oid): OidView {
		const read: OidRead = () => oid;
		const view = new OidView(read);
		return view;
	}

	/**
	 * A view of a copy of `name`, which the holder of the view owns. A holder
	 * with no release leaves the copy to the glue, which reclaims it with the
	 * holder.
	 */
	static copyOf(name: OidName): OidView {
		const copy = name.clone();
		const view = OidView.over(copy);
		return view;
	}

	/**
	 * A view that reads through `hold`, so a read after the owner released
	 * the hold refuses with the code of the hold, and never reaches the freed
	 * handle.
	 */
	static held(hold: Owned<Oid>): OidView {
		const read: OidRead = (operation) => hold.use(operation);
		const view = new OidView(read);
		return view;
	}

	/**
	 * A handle of its own that names the same object identifier.
	 */
	clone(): Oid {
		const oid = this.#oid("clone");
		const copy = oid.clone();
		return copy;
	}

	/**
	 * Whether `other` names the same object identifier, as the engine compares
	 * them.
	 */
	equals(other: OidName): boolean {
		const oid = this.#oid("equals");
		const compare = (named: Oid): boolean => oid.equals(named);
		const equal = Lent.oid(other, compare);
		return equal;
	}

	/**
	 * The dotted form.
	 */
	toString(): string {
		const oid = this.#oid("toString");
		const dotted = oid.toString();
		return dotted;
	}
}

/**
 * The object identifiers of the tightbeam profile, read once from the
 * constants of `tightbeam-rs` and owned by the engine of the realm. Each
 * member is a view, so no caller can release it under the realm.
 */
export class ProfileView {
	/**
	 * SHA3-256, the profile digest.
	 */
	readonly sha3_256: OidView;

	/**
	 * secp256k1 ECDSA over SHA3-256, the profile signature.
	 */
	readonly ecdsaWithSha3_256: OidView;

	/**
	 * AES-256-GCM, the profile symmetric cipher.
	 */
	readonly aes256Gcm: OidView;

	/**
	 * DHKEM over secp256k1, the profile recipient KEM.
	 */
	readonly dhkemSecp256k1: OidView;

	/**
	 * Zstandard, the profile compression.
	 */
	readonly zstd: OidView;

	/**
	 * zlib, interoperable with `CompressionStream("deflate")`.
	 */
	readonly zlib: OidView;

	/**
	 * id-data: the content type recorded in the compactness info, and in an
	 * envelope when the caller names none.
	 */
	readonly data: OidView;

	private constructor(oids: ProfileOids) {
		this.sha3_256 = OidView.over(oids.sha3_256);
		this.ecdsaWithSha3_256 = OidView.over(oids.ecdsaWithSha3_256);
		this.aes256Gcm = OidView.over(oids.aes256Gcm);
		this.dhkemSecp256k1 = OidView.over(oids.dhkemSecp256k1);
		this.zstd = OidView.over(oids.zstd);
		this.zlib = OidView.over(oids.zlib);
		this.data = OidView.over(oids.data);
	}

	/**
	 * The views of the handles that each getter of `oids` answers, read once.
	 * The holder of the view owns those handles, and `oids` itself stays the
	 * caller's to free.
	 */
	static read(oids: ProfileOids): ProfileView {
		const view = new ProfileView(oids);
		return view;
	}
}

/**
 * A digest that a frame owns, lent with no release.
 */
export class DigestInfoView implements DigestName {
	readonly #digest: DigestInfo;

	/**
	 * The algorithm that produced the digest.
	 */
	readonly algorithmOid: OidView;

	private constructor(digest: DigestInfo, algorithmOid: OidView) {
		this.#digest = digest;
		this.algorithmOid = algorithmOid;
	}

	/**
	 * A view of `digest`, which the caller keeps owning, and of the
	 * `algorithmOid` it read from it, which the caller owns with it.
	 */
	static over(digest: DigestInfo, algorithmOid: Oid): DigestInfoView {
		const algorithm = OidView.over(algorithmOid);
		const view = new DigestInfoView(digest, algorithm);
		return view;
	}

	/**
	 * A copy of the digest octets.
	 */
	get digest(): Uint8Array {
		const digest = this.#digest.digest;
		return digest;
	}

	/**
	 * A handle of its own that holds the same digest.
	 */
	clone(): DigestInfo {
		const copy = this.#digest.clone();
		return copy;
	}

	/**
	 * The verdict of the engine on `recomputed`, which `algorithmOid` produced,
	 * against this digest.
	 */
	verdict(algorithmOid: OidName, recomputed: Uint8Array): DigestVerdict {
		const judge = (named: Oid): DigestVerdict =>
			this.#digest.verdict(named, recomputed);

		const verdict = Lent.oid(algorithmOid, judge);
		return verdict;
	}
}

/**
 * A copy that one call borrows: cloned from a name the caller passed, and
 * freed as the call returns, however it returns. A holder that lends its own
 * handle to wasm this way never hands the handle itself to another holder.
 */
export class Lent {
	/**
	 * The answer of `use` over a copy of `name`.
	 */
	static oid<R>(name: OidName, use: (oid: Oid) => R): R {
		const copy = name.clone();
		try {
			const used = use(copy);
			return used;
		} finally {
			copy.free();
		}
	}

	/**
	 * The answer of `use` over a copy of `name`.
	 */
	static digest<R>(name: DigestName, use: (digest: DigestInfo) => R): R {
		const copy = name.clone();
		try {
			const used = use(copy);
			return used;
		} finally {
			copy.free();
		}
	}
}
