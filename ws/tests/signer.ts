/**
 * Shared external-signer fixture for the browser and Node e2e lanes.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";

import type { Engine, TransportSigner } from "@wahidgroup/tightbeam-ws-client";

/** ecdsa-with-SHA3-256 (NIST / TB profile). */
const ECDSA_WITH_SHA3_256 = "2.16.840.1.101.3.4.3.10";

/**
 * Copy `view` by index into a realm-local `Uint8Array`.
 *
 * Vitest/Vite can hand wasm-bindgen views across realms where
 * `Uint8Array.from(view)` / `.set(view)` mis-read bytes while index
 * access still returns the correct octets.
 */
function copyBytes(view: ArrayLike<number>): Uint8Array {
	const out = new Uint8Array(view.length);
	for (let index = 0; index < view.length; index += 1) {
		out[index] = Number(view[index]);
	}

	return out;
}

/**
 * A noble-backed {@link TransportSigner}, standing in for any external key
 * store (WebAuthn, wallet, KMS): the secret never crosses into wasm and
 * every prehash the handshake requests is counted.
 */
export class NobleTransportSigner implements TransportSigner {
	/**
	 * Dotted OID of ECDSA with SHA3-256, the profile signature algorithm.
	 */
	readonly algorithmOid = ECDSA_WITH_SHA3_256;

	/**
	 * How many prehashes the handshake asked this signer to sign.
	 */
	signatures = 0;

	/**
	 * DER SubjectPublicKeyInfo for the signing key, as the profile
	 * `Secp256k1SigningKey.toSpkiDer` of `engine` encodes it (profile
	 * `EncodePublicKey`, uncompressed SEC1).
	 */
	readonly publicKeyDer: Uint8Array;

	private readonly secret: Uint8Array;

	constructor(engine: Engine, secret: Uint8Array) {
		this.secret = copyBytes(secret);

		const key = engine.signingKey(this.secret);
		try {
			this.publicKeyDer = key.toSpkiDer();
		} finally {
			key[Symbol.dispose]();
		}
	}

	signPrehash(prehash: Uint8Array): Promise<Uint8Array> {
		this.signatures += 1;

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
