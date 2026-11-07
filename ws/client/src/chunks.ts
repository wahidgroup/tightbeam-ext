/**
 * The body chunks of a wasm stream handle, as one async iterable that owns
 * the handle.
 */

import type { MuxStreamBody } from "#wasm";

import type { StreamBody } from "./client.js";
import { ClientTransportError } from "./errors.js";
import { Owned } from "./owned.js";

/**
 * A wasm body handle. It yields one chunk per call until the peer's `last`,
 * and its free discards the chunks still to come.
 */
export type ChunkHandle = Pick<MuxStreamBody, "nextChunk" | "free">;

/**
 * The end of an iteration, as every read answers once the body ended.
 */
const ENDED: IteratorResult<Uint8Array> = { value: undefined, done: true };

/**
 * The chunks of a wasm body handle, read until `nextChunk` returns
 * `undefined`.
 *
 * The source owns the handle and frees it on every exit of the iteration:
 *
 * - The read of the peer's `last` frees it, and so does a read that fails.
 * - A `break` or a `return` in a `for await` loop frees it at once, and so does the end of an `await using`
 *   scope. Either one discards the chunks still to come.
 *
 * The body is single-use, as a generator is, and every iteration shares its
 * one generator. Overlapping `for await` loops queue their reads on it, so no
 * two reads reach the handle at once, and a `break` in any loop ends the body
 * for every loop. A `return` ends a read that still waits on the handle at
 * once and quietly, so the loop that waits ends with the loop that returned.
 */
export class ChunkSource implements StreamBody, AsyncIterator<Uint8Array> {
	readonly #hold: Owned<ChunkHandle>;

	readonly #chunks: AsyncGenerator<Uint8Array>;

	/**
	 * The end of each read in flight, which {@link return} runs so that a read
	 * that waits on the handle ends with the loop that returned. A read leaves
	 * the set as it settles, so the source holds nothing of a settled read.
	 */
	readonly #waiting = new Set<() => void>();

	constructor(handle: ChunkHandle) {
		this.#hold = new Owned(handle, ClientTransportError.streamClosed);
		this.#chunks = this.#read();
	}

	/**
	 * The source itself, so every iteration shares its one generator.
	 */
	[Symbol.asyncIterator](): this {
		return this;
	}

	/**
	 * The next chunk, read once every earlier read settled, or the end of the
	 * iteration once a {@link return} ran.
	 */
	next(): Promise<IteratorResult<Uint8Array>> {
		const read = this.#chunks.next();

		let end = (): void => undefined;
		const ended = new Promise<IteratorResult<Uint8Array>>((resolve) => {
			end = (): void => {
				resolve(ENDED);
			};
		});

		this.#waiting.add(end);
		void this.#forget(read, end);

		const next = Promise.race([read, ended]);
		return next;
	}

	/**
	 * Take `end` out of the set once `read` settles, either way.
	 */
	async #forget(
		read: Promise<IteratorResult<Uint8Array>>,
		end: () => void,
	): Promise<void> {
		try {
			await read;
		} catch {
			// The caller of next reads the refusal. A read that a return outran
			// may reject as its stream ends, and the return already ended every
			// loop, so that refusal is moot here.
		} finally {
			this.#waiting.delete(end);
		}
	}

	/**
	 * End the iteration for every loop and free the handle at once. A read
	 * that waits on the handle ends now, with no chunk and no refusal.
	 */
	async return(): Promise<IteratorResult<Uint8Array>> {
		this.#hold[Symbol.dispose]();
		for (const end of this.#waiting) {
			end();
		}
		this.#waiting.clear();

		// A read in flight holds its own share of the body in wasm, so the free
		// lands now, and the generator ends once that read settles.
		void this.#chunks.return(undefined);

		return ENDED;
	}

	/**
	 * End the iteration as {@link return} does.
	 */
	async [Symbol.asyncDispose](): Promise<void> {
		await this.return();
	}

	/**
	 * Yield the chunks of the handle in order, and free it as the generator
	 * ends, however it ends.
	 *
	 * A read that resumes after a `break` or a disposal ended the hold ends the
	 * generator without a refusal, so every loop queued on the body ends as
	 * the loop that broke out did.
	 */
	async *#read(): AsyncGenerator<Uint8Array> {
		try {
			for (;;) {
				const handle = this.#hold.held;
				if (handle === undefined) {
					return;
				}

				const chunk = await handle.nextChunk();
				if (chunk === undefined) {
					return;
				}

				yield chunk;
			}
		} finally {
			this.#hold[Symbol.dispose]();
		}
	}
}
