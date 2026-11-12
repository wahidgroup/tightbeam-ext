/**
 * The typed dispatch of server-initiated streams by frame id, as the routing section of `docs/ws-client.md` describes.
 */

import type { Envelope } from "./envelope.js";
import type { Frame } from "./frame.js";
import type { MessageCodec } from "./message.js";
import { StreamRefusal } from "./errors.js";

const TEXT = new TextDecoder();

/**
 * Answers one routed stream: receives the decoded message and the frame
 * that carried it, and returns (or resolves with) the response frame, or
 * `undefined` for a bodiless acceptance.
 */
export type RouteHandler<T> = (message: T, frame: Frame) => Promise<Frame | undefined> | Frame | undefined;

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
 * agrees. {@link Route.of} decodes a cleartext body under a codec, and
 * {@link Route.sealed} unwraps the frame under an envelope first.
 */
export class Route {
	private constructor(private readonly serve: (frame: Frame) => Promise<Frame | undefined>) {}

	/**
	 * Bind `codec` to `handle`: the cleartext body decodes under `codec`, and
	 * `handle` receives exactly the message type `codec` decodes. A sealed or
	 * compressed body refuses with `OpaqueBody`, so a route that reads one
	 * declares an envelope through {@link Route.sealed}.
	 */
	static of<T>(codec: MessageCodec<T>, handle: RouteHandler<T>): Route {
		const serve = async (frame: Frame): Promise<Frame | undefined> => {
			const message = await frame.open(codec);
			const response = await handle(message, frame);
			return response;
		};

		const route = new Route(serve);
		return route;
	}

	/**
	 * Bind `envelope` to `handle`: each frame unwraps under the envelope's
	 * declared layers before `handle` runs. An envelope that declares `signed`
	 * refuses an unsigned or forged frame, and one that declares `sealed`
	 * refuses a cleartext frame, before any decode.
	 */
	static sealed<T>(envelope: Envelope<T, boolean, true>, handle: RouteHandler<T>): Route {
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
 * A table of id-prefix routes, served as one stream handler. The frame id decodes as UTF-8, and the longest matching
 * prefix wins whatever the table order. An id that no prefix matches throws {@link UnroutedTopicError}. The routing
 * section of `docs/ws-client.md` shows a router whose dispatch serves each stream.
 */
export class Router {
	private readonly byLongestPrefix: readonly (readonly [string, Route])[];

	/**
	 * Serve `table`, which maps each id prefix to its route.
	 */
	constructor(table: Readonly<Record<string, Route>>) {
		const entries = Object.entries(table);
		this.byLongestPrefix = entries.sort(([left], [right]) => right.length - left.length);
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
