/**
 * The server-initiated streams that a `serve*` handler answers, over the wasm
 * handles of their body and their reply.
 */

import type { MuxReplySink, StreamRoute, TransitRefusal } from "#wasm";

import type { ChunkHandle } from "./chunks.js";
import type { EngineParts } from "./engine.js";
import type { DuplexBodyHandler, MuxStreamHandler, ReplySink, StreamingBodyHandler } from "./client.js";
import { ChunkSource } from "./chunks.js";
import { StreamRefusal } from "./errors.js";
import { Frame } from "./frame.js";
import { PushHalf } from "./push.js";

/**
 * A wasm reply handle, which pushes one reply chunk per call toward the peer.
 */
export type ReplyHandle = Pick<MuxReplySink, "push" | "free">;

/**
 * The reply half of a served duplex stream. Its {@link PushHalf} orders its
 * pushes and releases its wasm handle.
 */
class ServedReply implements ReplySink {
	readonly #half: PushHalf<ReplyHandle>;

	constructor(handle: ReplyHandle) {
		this.#half = new PushHalf(handle);
	}

	push(chunk: Uint8Array): Promise<void> {
		const pushed = this.#half.push(chunk);
		return pushed;
	}

	async [Symbol.asyncDispose](): Promise<void> {
		this.#half[Symbol.dispose]();
	}
}

/**
 * One server-initiated stream that a `serve*` handler answers: its body, and
 * the reply half of a duplex stream. It frees both handles once the handler
 * settles, and a body that the handler ends first frees at once. A throw of
 * the handler answers the label that {@link StreamRefusal.settlement} decides.
 */
export class ServedStream implements AsyncDisposable {
	readonly #body: ChunkSource;

	readonly #reply: ServedReply | undefined;

	private constructor(body: ChunkSource, reply: ServedReply | undefined) {
		this.#body = body;
		this.#reply = reply;
	}

	/**
	 * The answer that a handler settled with, as the engine sends it: the DER
	 * of the response frame, or `undefined` for a bodiless acceptance, which
	 * `null` names too.
	 */
	static #answer(response: Frame | undefined | null): Uint8Array | undefined {
		if (response === undefined || response === null) {
			return undefined;
		}

		const responseDer = response.toDer();
		return responseDer;
	}

	/**
	 * The outcome of `handling`, or a rejection with the status label that
	 * {@link StreamRefusal.settlement} decides for its throw.
	 */
	static async #settled<T>(handling: () => Promise<T>): Promise<T> {
		try {
			const outcome = await handling();
			return outcome;
		} catch (thrown) {
			const label: TransitRefusal = StreamRefusal.settlement(thrown);
			throw label;
		}
	}

	/**
	 * Answer a served unary stream with `handler`, which reads the request
	 * frame that `requestDer` encodes, decoded through the engine `parts`.
	 *
	 * @internal
	 */
	static answerUnary(
		parts: EngineParts,
		handler: MuxStreamHandler,
		requestDer: Uint8Array,
	): Promise<Uint8Array | undefined> {
		const answered = ServedStream.#settled(async () => {
			const request = Frame.decode(parts, requestDer);
			const response = await handler(request);
			return ServedStream.#answer(response);
		});
		return answered;
	}

	/**
	 * Answer a served progressive stream with `handler`, which reads the
	 * chunks of `body` and the Open's `route`.
	 */
	static answerStreaming(
		handler: StreamingBodyHandler,
		body: ChunkHandle,
		route: StreamRoute,
	): Promise<Uint8Array | undefined> {
		const answered = ServedStream.#settled(async () => {
			const chunks = new ChunkSource(body);
			await using _served = new ServedStream(chunks, undefined);
			const response = await handler(chunks, route);
			return ServedStream.#answer(response);
		});
		return answered;
	}

	/**
	 * Answer a served duplex stream with `handler`, which reads the chunks of
	 * `body`, pushes through `reply`, and reads the Open's `route`, and
	 * resolve with the refusal the handler settles with, or `undefined` for
	 * `Ok`.
	 */
	static answerDuplex(
		handler: DuplexBodyHandler,
		body: ChunkHandle,
		reply: ReplyHandle,
		route: StreamRoute,
	): Promise<TransitRefusal | undefined> {
		const answered = ServedStream.#settled(async () => {
			const chunks = new ChunkSource(body);
			const replies = new ServedReply(reply);
			await using _served = new ServedStream(chunks, replies);
			const status = await handler(chunks, replies, route);
			if (status === undefined) {
				return undefined;
			}

			return status;
		});
		return answered;
	}

	/**
	 * Free the body and the reply handles, each one once.
	 */
	async [Symbol.asyncDispose](): Promise<void> {
		await this.#body[Symbol.asyncDispose]();
		await this.#reply?.[Symbol.asyncDispose]();
	}
}
