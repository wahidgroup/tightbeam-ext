/**
 * Shared external-signer fixture for the browser and Node e2e lanes.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";

import type { TransportSigner } from "@wahidgroup/tightbeam-ws-client";

/**
 * DER SubjectPublicKeyInfo prefix for a compressed secp256k1 point:
 * SEQUENCE { SEQUENCE { id-ecPublicKey, secp256k1 }, BIT STRING (33 bytes) }.
 */
const SPKI_COMPRESSED_PREFIX = new Uint8Array([
	0x30, 0x36, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
	0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x22, 0x00,
]);

/**
 * A noble-backed {@link TransportSigner}, standing in for any external key
 * store (WebAuthn, wallet, KMS): the secret never crosses into wasm and
 * every prehash the handshake requests is counted.
 */
export class NobleTransportSigner implements TransportSigner {
	/**
	 * Dotted OID of ECDSA with SHA-256, the profile signature algorithm.
	 */
	readonly algorithmOid = "1.2.840.10045.4.3.2";

	/**
	 * DER SubjectPublicKeyInfo for the signing key, derived from the
	 * secret at construction.
	 */
	readonly publicKeyDer: Uint8Array;

	/**
	 * How many prehashes the handshake asked this signer to sign.
	 */
	signatures = 0;

	constructor(private readonly secret: Uint8Array) {
		const point = secp256k1.getPublicKey(secret, true);
		this.publicKeyDer = new Uint8Array([
			...SPKI_COMPRESSED_PREFIX,
			...point,
		]);
	}

	signPrehash(prehash: Uint8Array): Promise<Uint8Array> {
		this.signatures += 1;

		const signature = secp256k1.sign(prehash, this.secret, {
			prehash: false,
		});

		const settled = Promise.resolve(signature);
		return settled;
	}
}
