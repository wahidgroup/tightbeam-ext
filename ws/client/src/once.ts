/**
 * A start that runs once per realm, as the build section of `docs/ws-wasm.md` describes.
 */

/**
 * A start that runs once and answers every later call with the same start.
 * A start that rejects clears the memo, so the next call starts again.
 */
export class Once<T> {
	#started: Promise<T> | undefined;

	/**
	 * The start in flight or done, or the start that `start` begins now.
	 */
	run(start: () => Promise<T>): Promise<T> {
		const held = this.#started;
		if (held !== undefined) {
			return held;
		}

		const starting = start();
		this.#started = starting;
		void starting.catch(() => {
			this.#started = undefined;
		});

		return starting;
	}
}
