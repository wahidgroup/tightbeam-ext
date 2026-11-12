/**
 * A signer that the unit tests bring, in the shape of a WebAuthn prompt or a wallet.
 */

import type { Secp256k1SigningKey, Signatory } from "../crypto.js";

/**
 * The refusal a WebAuthn prompt answers when the person declines it.
 */
const DECLINED = new DOMException("the person declined", "NotAllowedError");

/**
 * A signatory that declines each prompt until the person approves, and then
 * signs with a real engine key.
 */
export class PromptedSigner implements Signatory {
	readonly #key: Secp256k1SigningKey;

	#approved = false;

	constructor(key: Secp256k1SigningKey) {
		this.#key = key;
	}

	/**
	 * Approve every later prompt.
	 */
	approve(): void {
		this.#approved = true;
	}

	signerId(): Uint8Array {
		const signerId = this.#key.signerId();
		return signerId;
	}

	async signPrehash(prehash: Uint8Array): Promise<Uint8Array> {
		if (!this.#approved) {
			throw DECLINED;
		}

		const signature = await this.#key.signPrehash(prehash);
		return signature;
	}
}
