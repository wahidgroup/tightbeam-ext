/**
 * The external transport signer of the browser and Node e2e lanes.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";

import type { Engine, TransportSigner } from "@wahidgroup/tightbeam-ws-client";

/**
 * Copy `view` by index into a `Uint8Array` of this realm, because a view that
 * crossed from the wasm realm reads true by index alone.
 */
function copyBytes(view: ArrayLike<number>): Uint8Array {
	const out = new Uint8Array(view.length);
	for (let index = 0; index < view.length; index += 1) {
		out[index] = Number(view[index]);
	}

	return out;
}

/**
 * A noble-backed {@link TransportSigner}, which stands in for an external key store such as WebAuthn, a wallet, or KMS.
 * The secret stays in this signer, outside the wasm module.
 */
export class NobleTransportSigner implements TransportSigner {
	/**
	 * The dotted OID of the profile signature, ECDSA over SHA3-256.
	 */
	readonly algorithmOid: string;

	/**
	 * DER SubjectPublicKeyInfo for the signing key, as the profile
	 * `Secp256k1SigningKey.toSpkiDer` of `engine` encodes it (profile
	 * `EncodePublicKey`, uncompressed SEC1).
	 */
	readonly publicKeyDer: Uint8Array;

	private readonly secret: Uint8Array;

	/**
	 * The signer of `secret`, whose public key and algorithm `engine` names.
	 */
	constructor(engine: Engine, secret: Uint8Array) {
		this.algorithmOid = engine.profile.ecdsaWithSha3_256.toString();
		this.secret = copyBytes(secret);

		using key = engine.signingKey(this.secret);
		this.publicKeyDer = key.toSpkiDer();
	}

	/**
	 * Sign `prehash` with the secret, as a DER signature of low S.
	 */
	signPrehash(prehash: Uint8Array): Promise<Uint8Array> {
		const digest = copyBytes(prehash);
		const signature = secp256k1.sign(digest, this.secret, {
			prehash: false,
			format: "der",
			lowS: true,
		});

		const bytes = copyBytes(signature);
		const settled = Promise.resolve(bytes);
		return settled;
	}
}
