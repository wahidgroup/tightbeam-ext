/**
 * Noble-backed Signatory / FrameVerifier fixtures for unit tests. The
 * secret never enters wasm; stands in for wallets, HSMs, and other BYO
 * authenticity implementations.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha3_256 } from "@noble/hashes/sha3.js";

import type { FrameVerifier, Signatory, VerifiableFrame } from "../crypto.js";
import { PROFILE_OIDS, Secp256k1VerifyingKey } from "../crypto.js";

/**
 * Verify a frame from `tbs` + carried signature bytes with noble secp256k1.
 * Stands in for any non-wasm verifier (wallet SDK, ed25519, …).
 */
export class NobleFrameVerifier implements FrameVerifier {
	constructor(private readonly publicKey: Uint8Array) {}

	verifyFrame(frame: VerifiableFrame): void {
		const info = frame.signatureInfo;
		if (info === undefined) {
			throw new Error("frame is unsigned");
		}

		if (info.algorithmOid !== PROFILE_OIDS.ecdsaWithSha3_256) {
			throw new Error("unexpected signature algorithm");
		}

		const digest = sha3_256(frame.tbs());
		const ok = secp256k1.verify(info.signature, digest, this.publicKey, {
			prehash: false,
		});
		if (!ok) {
			throw new Error("signature verification failed");
		}
	}
}

/**
 * A {@link Signatory} whose secret never enters wasm. Optional TBS capture
 * for boundary-order assertions.
 */
export class NobleSignatory implements Signatory {
	readonly signatureAlgorithmOid = PROFILE_OIDS.ecdsaWithSha3_256;
	readonly digestAlgorithmOid = PROFILE_OIDS.sha3_256;
	readonly verifier: FrameVerifier;
	readonly seen: Uint8Array[] = [];

	constructor(private readonly secret: Uint8Array) {
		this.verifier = new NobleFrameVerifier(
			secp256k1.getPublicKey(secret, true),
		);
	}

	/**
	 * Compressed SEC1 public key for this secret.
	 */
	publicKey(): Uint8Array {
		const publicKey = secp256k1.getPublicKey(this.secret, true);
		return publicKey;
	}

	signerId(): Uint8Array {
		const id = Secp256k1VerifyingKey.fromSec1Bytes(
			this.publicKey(),
		).signerId();
		return id;
	}

	sign(tbs: Uint8Array): Promise<Uint8Array> {
		this.seen.push(tbs);
		const digest = sha3_256(tbs);
		const signature = secp256k1.sign(digest, this.secret, {
			prehash: false,
		});
		const result = Promise.resolve(signature);
		return result;
	}
}
