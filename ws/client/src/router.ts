/**
 * Typed dispatch for server-initiated streams.
 *
 * A serve handler receives every stream the server opens, so applications
 * demultiplex by frame id. The router makes that pairing checkable: each route
 * binds an id prefix to a codec or an envelope and a handler whose message
 * type it proves, so the decoder and its handler cannot disagree at compile
 * time.
 */

import type { Envelope } from "./envelope.js";
import type { Frame } from "./frame.js";
import type { MessageCodec } from "./message.js";
import { StreamRefusal } from "./errors.js";

const TEXT = new TextDecoder();

/**
 * Answers one routed stream: receives the decoded message and the frame
 * it rode in on, and returns (or resolves with) the response frame, or
 * `undefined` for a bodiless acceptance.
 */
export type RouteHandler<T> = (
	message: T,
	frame: Frame,
) => Promise<Frame | undefined> | Frame | undefined;

/**
 * A server-initiated stream arrived with an id no route matches. Thrown
 * from the routed handler. Its `Unimplemented` code answers the stream.
 */
export class UnroutedTopicError extends StreamRefusal {
	override readonly name: string = "UnroutedTopicError";

	/**
	 * Frame id prefix that no registered route claimed.
	 */
	readonly topic: string;

	constructor(topic: string) {
		super("Unimplemented", `no route matches topic: ${topic}`);
		this.topic = topic;
	}
}

/**
 * One dispatch table entry: a decoder and handler pair whose message type
 * agrees.
 *
 * - {@link Route.of} decodes a cleartext body under a codec.
 * - {@link Route.sealed} unwraps under an envelope, so a declared signature
 *   verifies and a declared seal opens before the handler sees a message.
 */
export class Route {
	private constructor(
		private readonly serve: (frame: Frame) => Promise<Frame | undefined>,
	) {}

	/**
	 * Bind `codec` to `handle`: the cleartext body decodes under `codec`, and
	 * `handle` receives exactly the message type `codec` decodes.
	 */
	static of<T>(codec: MessageCodec<T>, handle: RouteHandler<T>): Route {
		const serve = async (frame: Frame): Promise<Frame | undefined> => {
			const message = frame.message(codec);
			const response = await handle(message, frame);
			return response;
		};

		const route = new Route(serve);
		return route;
	}

	/**
	 * Bind `envelope` to `handle`: each frame unwraps under the envelope's
	 * declared layers before `handle` runs, so a route that declares
	 * `signed` or `verified` refuses an unsigned or forged frame before
	 * any decode.
	 */
	static sealed<T>(envelope: Envelope<T>, handle: RouteHandler<T>): Route {
		const serve = async (frame: Frame): Promise<Frame | undefined> => {
			const message = await envelope.unwrap(frame);
			const response = await handle(message, frame);
			return response;
		};

		const route = new Route(serve);
		return route;
	}

	/**
	 * Decode the frame's message and run the handler.
	 */
	dispatch(frame: Frame): Promise<Frame | undefined> {
		const response = this.serve(frame);
		return response;
	}
}

/**
 * A table of id-prefix routes, served as one stream handler.
 *
 * The frame id decodes as UTF-8 and the longest matching prefix wins, so
 * `"tick/spot/"` shadows `"tick/"` regardless of table order. An id no
 * prefix matches throws {@link UnroutedTopicError}, answering the stream
 * with an `Unimplemented` status.
 *
 * ```ts
 * const routes = new Router({
 * 	"tick/": Route.of(TickCodec, (tick) => {
 * 		store.applyTick(tick);
 * 		return undefined;
 * 	}),
 * 	"chat/": Route.sealed(chat, (message, request) => {
 * 		store.appendChat(message);
 * 		return receipt(request);
 * 	}),
 * });
 *
 * client.serve((request) => routes.dispatch(request));
 * ```
 */
export class Router {
	private readonly byLongestPrefix: readonly (readonly [string, Route])[];

	/**
	 * Serve `table`, which maps each id prefix to its route.
	 */
	constructor(table: Readonly<Record<string, Route>>) {
		const entries = Object.entries(table);
		this.byLongestPrefix = entries.sort(
			([left], [right]) => right.length - left.length,
		);
	}

	/**
	 * Run the route whose prefix is the longest match for the frame id.
	 *
	 * @throws UnroutedTopicError when no prefix matches.
	 */
	async dispatch(frame: Frame): Promise<Frame | undefined> {
		const topic = TEXT.decode(frame.id);
		for (const [prefix, route] of this.byLongestPrefix) {
			if (topic.startsWith(prefix)) {
				const response = await route.dispatch(frame);
				return response;
			}
		}

		throw new UnroutedTopicError(topic);
	}
}
