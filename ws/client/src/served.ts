/**
 * The server-initiated streams that a `serve*` handler answers, over the wasm
 * handles of their body and their reply.
 */

import type { MuxReplySink } from "#wasm";

import type { ChunkHandle } from "./chunks.js";
import type { RefusalStatus } from "./errors.js";
import type {
	DuplexBodyHandler,
	ReplySink,
	StreamRoute,
	StreamingBodyHandler,
} from "./client.js";
import { ChunkSource } from "./chunks.js";
import { ClientTransportError } from "./errors.js";
import { Owned } from "./owned.js";

/**
 * A wasm reply handle, which pushes one reply chunk per call toward the peer.
 */
export type ReplyHandle = Pick<MuxReplySink, "push" | "free">;

/**
 * The reply half of a served duplex stream, over its wasm handle.
 */
class ServedReply implements ReplySink {
	readonly #hold: Owned<ReplyHandle>;

	constructor(handle: ReplyHandle) {
		this.#hold = new Owned(handle, ClientTransportError.streamClosed);
	}

	async push(chunk: Uint8Array): Promise<void> {
		const handle = this.#hold.use("push a reply chunk");
		await handle.push(chunk);
	}

	async [Symbol.asyncDispose](): Promise<void> {
		this.#hold[Symbol.dispose]();
	}
}

/**
 * One server-initiated stream that a `serve*` handler answers: its body, and
 * the reply half of a duplex stream.
 *
 * The served stream owns the wasm handle of each, and frees both once the
 * handler settles, whether the handler resolves or throws. A body that the
 * handler ends first frees at once, and a push after the free refuses with
 * `StreamClosed`.
 */
export class ServedStream implements AsyncDisposable {
	readonly #body: ChunkSource;

	readonly #reply: ServedReply | undefined;

	private constructor(body: ChunkSource, reply: ServedReply | undefined) {
		this.#body = body;
		this.#reply = reply;
	}

	/**
	 * Answer a served progressive stream with `handler`, which reads the
	 * chunks of `body` and the Open's `route`, and resolve with the DER of
	 * the response frame, or `undefined` for a bodiless acceptance.
	 */
	static async answerStreaming(
		handler: StreamingBodyHandler,
		body: ChunkHandle,
		route: StreamRoute,
	): Promise<Uint8Array | undefined> {
		const chunks = new ChunkSource(body);
		const served = new ServedStream(chunks, undefined);
		try {
			const response = await handler(chunks, route);
			if (response === undefined || response === null) {
				return undefined;
			}

			const responseDer = response.toDer();
			return responseDer;
		} finally {
			await served[Symbol.asyncDispose]();
		}
	}

	/**
	 * Answer a served duplex stream with `handler`, which reads the chunks of
	 * `body`, pushes through `reply`, and reads the Open's `route`, and
	 * resolve with the status the handler settles with, or `undefined` for
	 * `Ok`.
	 */
	static async answerDuplex(
		handler: DuplexBodyHandler,
		body: ChunkHandle,
		reply: ReplyHandle,
		route: StreamRoute,
	): Promise<RefusalStatus | undefined> {
		const chunks = new ChunkSource(body);
		const replies = new ServedReply(reply);
		const served = new ServedStream(chunks, replies);
		try {
			const status = await handler(chunks, replies, route);
			if (status === undefined) {
				return undefined;
			}

			return status;
		} finally {
			await served[Symbol.asyncDispose]();
		}
	}

	/**
	 * Free the body and the reply handles, each one once.
	 */
	async [Symbol.asyncDispose](): Promise<void> {
		await this.#body[Symbol.asyncDispose]();
		await this.#reply?.[Symbol.asyncDispose]();
	}
}
