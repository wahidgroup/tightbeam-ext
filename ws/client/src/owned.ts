/**
 * The hold of a wasm object by the one TypeScript class that owns it.
 */

/**
 * A wasm object as its owner releases it: the glue `free` drops the Rust
 * value behind it.
 */
export interface WasmObject {
	/**
	 * Drop the Rust value. A second call throws, because the glue nulls its
	 * pointer on the first.
	 */
	free(): void;
}

/**
 * The error that refuses `operation` on a wasm object whose hold ended.
 */
export type Refusal = (operation: string) => Error;

/**
 * One wasm object, held by the TypeScript class that owns it until a free or
 * a consuming wasm call ends the hold. A hold ends once, so the object frees
 * once, and every call after the end refuses with the refusal the hold was
 * built with.
 */
export class Owned<T extends WasmObject> implements Disposable {
	#held: T | undefined;

	readonly #refusal: Refusal;

	constructor(object: T, refusal: Refusal) {
		this.#held = object;
		this.#refusal = refusal;
	}

	/**
	 * The object, for `operation`, a call that leaves the hold as it is.
	 *
	 * @throws The refusal of `operation` once the hold ended.
	 */
	use(operation: string): T {
		const held = this.#held;
		if (held === undefined) {
			throw this.#refusal(operation);
		}

		return held;
	}

	/**
	 * The object while the hold lasts, or `undefined` once it ended, for an
	 * owner whose reads end quietly with the hold.
	 */
	get held(): T | undefined {
		return this.#held;
	}

	/**
	 * End the hold and hand the object to `operation`, a wasm call that
	 * consumes it.
	 *
	 * @throws The refusal of `operation` once the hold ended.
	 */
	take(operation: string): T {
		const taken = this.use(operation);
		this.#held = undefined;
		return taken;
	}

	/**
	 * End the hold and free the object. A hold that already ended stays as it
	 * is.
	 */
	[Symbol.dispose](): void {
		const released = this.#held;
		this.#held = undefined;
		released?.free();
	}
}
