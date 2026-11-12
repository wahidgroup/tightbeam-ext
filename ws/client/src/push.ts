/**
 * The push half of a wasm stream, which runs its calls in the order they were
 * made.
 */

import type { WasmObject } from "./owned.js";
import { ClientTransportError } from "./errors.js";
import { Owned } from "./owned.js";

/**
 * A wasm push half, which pushes one chunk per call toward the peer: the
 * request half of a client-initiated stream, or the reply half of a served
 * duplex stream.
 */
export interface PushHandle extends WasmObject {
	/**
	 * Push one chunk toward the peer. An empty chunk sends nothing.
	 */
	push(chunk: Uint8Array): Promise<void>;
}

/**
 * The push half of a stream: its wasm handle, and the one tail that every
 * call on the half waits behind. A call that waits reads a copy of its chunk,
 * so a later write to the chunk leaves the call as made. A call after a close
 * or a disposal refuses with `StreamClosed`.
 */
export class PushHalf<T extends PushHandle> implements Disposable {
	readonly #hold: Owned<T>;

	/**
	 * The last call on the half, settled either way.
	 */
	#tail: Promise<void> = Promise.resolve();

	/**
	 * The calls that have not settled yet.
	 */
	#queued = 0;

	constructor(stream: T) {
		this.#hold = new Owned(stream, ClientTransportError.streamClosed);
	}

	/**
	 * Push `chunk` at its turn.
	 */
	push(chunk: Uint8Array): Promise<void> {
		const octets = this.#readable(chunk);
		const pushing = async (): Promise<void> => {
			const stream = this.#hold.use("push");
			await stream.push(octets);
		};

		const pushed = this.#after(pushing);
		return pushed;
	}

	/**
	 * Run `closing`, the close `operation`, at its turn over the handle that
	 * it consumes.
	 */
	close<R>(operation: string, closing: (stream: T) => Promise<R>): Promise<R> {
		const turn = async (): Promise<R> => {
			const stream = this.#hold.take(operation);
			const closed = await closing(stream);
			return closed;
		};

		const closed = this.#after(turn);
		return closed;
	}

	/**
	 * Run `closing`, which pushes `chunk` as the final chunk, at its turn over
	 * the handle that it consumes.
	 */
	closeWith<R>(chunk: Uint8Array, closing: (stream: T, last: Uint8Array) => Promise<R>): Promise<R> {
		const octets = this.#readable(chunk);
		const finishing = (stream: T): Promise<R> => closing(stream, octets);

		const closed = this.close("closeWith", finishing);
		return closed;
	}

	/**
	 * Free an open handle at once. A push in flight holds its own share of the
	 * half in wasm, so the half drops once that push settles, and the drop of
	 * a request half cancels its stream.
	 */
	[Symbol.dispose](): void {
		this.#hold[Symbol.dispose]();
	}

	/**
	 * `chunk` as a call reads it: the chunk itself when the call starts at
	 * once, and a copy when the call waits behind another.
	 */
	#readable(chunk: Uint8Array): Uint8Array {
		if (this.#queued === 0) {
			return chunk;
		}

		// The constructor copies a Node `Buffer` too, whose `slice` is a view.
		const copy = new Uint8Array(chunk);
		return copy;
	}

	/**
	 * Run `turn` once the call before it settles, or at once when no call is
	 * pending.
	 */
	#after<R>(turn: () => Promise<R>): Promise<R> {
		const previous = this.#tail;
		const waits = this.#queued > 0;
		const run = async (): Promise<R> => {
			if (waits) {
				await previous;
			}

			try {
				const ran = await turn();
				return ran;
			} finally {
				this.#queued -= 1;
			}
		};

		this.#queued += 1;
		const running = run();
		this.#tail = PushHalf.#settled(running);
		return running;
	}

	/**
	 * Settle once `pending` settles, whether it resolves or rejects.
	 */
	static async #settled(pending: Promise<unknown>): Promise<void> {
		try {
			await pending;
		} catch {
			// The caller of the call receives its failure.
		}
	}
}
