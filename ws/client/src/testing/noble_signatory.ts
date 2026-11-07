/**
 * Noble-backed Signatory / FrameVerifier fixtures for unit tests. The
 * secret never enters wasm; stands in for wallets, HSMs, and other BYO
 * authenticity implementations.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";

import type { FrameVerifier, Signatory, VerifiableFrame } from "../crypto.js";
import type { Engine } from "../engine.js";

/**
 * Verify a frame from its signature prehash + carried signature bytes with
 * noble secp256k1. Stands in for any non-wasm verifier (wallet SDK, …).
 */
export class NobleFrameVerifier implements FrameVerifier {
	constructor(
		private readonly engine: Engine,
		private readonly publicKey: Uint8Array,
	) {}

	verifyFrame(frame: VerifiableFrame): void {
		const info = frame.signatureInfo;
		if (info === undefined) {
			throw new Error("frame is unsigned");
		}

		const profile = this.engine.profile.ecdsaWithSha3_256;
		if (!info.algorithmOid.equals(profile)) {
			throw new Error("unexpected signature algorithm");
		}

		const ok = secp256k1.verify(
			info.signature,
			frame.signaturePrehash(),
			this.publicKey,
			{ format: "der", prehash: false },
		);
		if (!ok) {
			throw new Error("signature verification failed");
		}
	}
}

/**
 * A {@link Signatory} whose secret never enters wasm.
 */
export class NobleSignatory implements Signatory {
	readonly verifier: FrameVerifier;

	constructor(
		private readonly engine: Engine,
		private readonly secret: Uint8Array,
	) {
		const publicKey = secp256k1.getPublicKey(secret, true);
		this.verifier = new NobleFrameVerifier(engine, publicKey);
	}

	/**
	 * Compressed SEC1 public key for this secret.
	 */
	publicKey(): Uint8Array {
		const publicKey = secp256k1.getPublicKey(this.secret, true);
		return publicKey;
	}

	signerId(): Uint8Array {
		const key = this.engine.verifyingKey(this.publicKey());
		const id = key.signerId();
		key[Symbol.dispose]();
		return id;
	}

	signPrehash(prehash: Uint8Array): Promise<Uint8Array> {
		const signature = secp256k1.sign(prehash, this.secret, {
			format: "der",
			prehash: false,
		});

		const result = Promise.resolve(signature);
		return result;
	}
}
