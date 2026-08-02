/**
 * Shared external-signer fixture for the browser and Node e2e lanes.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";

import type { TransportSigner } from "@wahidgroup/tightbeam-ws-client";

/** ecdsa-with-SHA3-256 (NIST / TB profile). */
const ECDSA_WITH_SHA3_256 = "2.16.840.1.101.3.4.3.10";

/**
 * DER SubjectPublicKeyInfo prefix for an uncompressed secp256k1 point:
 * SEQUENCE { SEQUENCE { id-ecPublicKey, secp256k1 }, BIT STRING (65 bytes) }.
 *
 * MUST match the SPKI encoding in the client certificate. Receipt
 * countersign SID is `SHA3-256(publicKeyDer)[..20]`. The server expects
 * that SID to equal the cert's SPKI digest. Compressed vs uncompressed
 * DER hashes diverge even when the point is the same.
 */
const SPKI_UNCOMPRESSED_PREFIX = new Uint8Array([
	0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
	0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
]);

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
	 * DER SubjectPublicKeyInfo for the signing key, derived from the
	 * secret at construction.
	 */
	readonly publicKeyDer: Uint8Array;

	/**
	 * How many prehashes the handshake asked this signer to sign.
	 */
	signatures = 0;

	private readonly secret: Uint8Array;

	constructor(secret: Uint8Array) {
		this.secret = copyBytes(secret);

		const point = secp256k1.getPublicKey(this.secret, false);
		this.publicKeyDer = new Uint8Array([
			...SPKI_UNCOMPRESSED_PREFIX,
			...point,
		]);
	}

	signPrehash(prehash: Uint8Array): Promise<Uint8Array> {
		this.signatures += 1;

		const digest = copyBytes(prehash);
		const signature = secp256k1.sign(digest, this.secret, {
			prehash: false,
			format: "compact",
			lowS: true,
		});

		const bytes = copyBytes(signature);
		const settled = Promise.resolve(bytes);
		return settled;
	}
}
