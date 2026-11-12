/**
 * The frame of one build between its security steps, which owns its one live
 * wasm handle.
 */

import type { FrameAssembly, FrameComposer } from "#wasm";

import type { Signatory } from "../crypto.js";

/**
 * The frame of one build between its security steps. Each step consumes this
 * frame and returns the next one, so a build holds one live handle at a time.
 * A step whose external work rejects frees the handle, and a step that wasm
 * refuses drops it in wasm.
 */
export class Assembled {
	readonly #live: FrameAssembly;

	private constructor(live: FrameAssembly) {
		this.#live = live;
	}

	/**
	 * The structural frame that `composer` assembles. The assembly consumes
	 * the composer, whether it builds or refuses.
	 *
	 * @throws TightbeamTransportError with the refusal of the engine, such as
	 * `UnsupportedField` or `VersionMismatch`.
	 */
	static of(composer: FrameComposer): Assembled {
		const live = composer.build();
		const assembled = new Assembled(live);
		return assembled;
	}

	/**
	 * Run `work` over this frame, then install its outcome through `step`,
	 * which consumes this frame, and answer the frame `step` returns.
	 *
	 * `work` runs the caller's own cryptography, such as a hash or a seal, so
	 * it may reject. A rejection frees this frame.
	 */
	async after<R>(
		work: (live: FrameAssembly) => Promise<R> | R,
		step: (live: FrameAssembly, outcome: R) => FrameAssembly,
	): Promise<Assembled> {
		let outcome: R;
		try {
			outcome = await work(this.#live);
		} catch (refusal) {
			this.#live.free();
			throw refusal;
		}

		const next = step(this.#live, outcome);
		const assembled = new Assembled(next);
		return assembled;
	}

	/**
	 * The frame that `signatory` signs. The engine drafts the signature over
	 * this frame, which the draft consumes, and the signatory signs its
	 * prehash. A refused draft or signature frees what the build holds.
	 */
	async sign(signatory: Signatory): Promise<Assembled> {
		let signerId: Uint8Array;
		try {
			signerId = signatory.signerId();
		} catch (refusal) {
			this.#live.free();
			throw refusal;
		}

		const signing = this.#live.signing(signerId);
		let signature: Uint8Array;
		try {
			signature = await signatory.signPrehash(signing.prehash);
		} catch (refusal) {
			signing.free();
			throw refusal;
		}

		const signed = signing.complete(signature);
		const assembled = new Assembled(signed);
		return assembled;
	}

	/**
	 * The DER of the finished frame. The build ends here, so the read frees
	 * the frame.
	 */
	encode(): Uint8Array {
		try {
			const der = this.#live.encode();
			return der;
		} finally {
			this.#live.free();
		}
	}
}
