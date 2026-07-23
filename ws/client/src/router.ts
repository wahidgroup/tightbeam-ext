/**
 * Typed dispatch for server-initiated streams.
 *
 * A serve handler receives every stream the server opens, so applications
 * demultiplex by frame id. The router makes that pairing checkable: each route
 * binds an id prefix to a codec and a handler whose message type the codec
 * proves, so a codec and its handler cannot disagree at compile time.
 */

import { StreamRefusal } from "./errors.js";
import type { Frame } from "./frame.js";
import type { MessageCodec } from "./message.js";

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
 * One dispatch table entry: a codec and handler pair whose message type
 * agrees. Build with {@link route}.
 */
export interface Route {
	/**
	 * Decode the frame's message and run the handler.
	 */
	dispatch(frame: Frame): Promise<Frame | undefined>;
}

/**
 * A server-initiated stream arrived with an id no route matches. Thrown
 * from the routed handler; its `Unimplemented` code answers the stream.
 */
export class UnroutedTopicError extends StreamRefusal {
	override readonly name: string = "UnroutedTopicError";

	constructor(readonly topic: string) {
		super("Unimplemented", `no route matches topic: ${topic}`);
	}
}

/**
 * Bind `codec` to `handle` as one dispatch table entry.
 *
 * The compiler enforces the pairing: `handle` receives exactly the message
 * type `codec` decodes.
 */
export function route<T>(
	codec: MessageCodec<T>,
	handle: RouteHandler<T>,
): Route {
	const entry: Route = {
		async dispatch(frame: Frame): Promise<Frame | undefined> {
			const message = frame.message(codec);
			const response = await handle(message, frame);
			return response;
		},
	};
	return entry;
}

/**
 * Build a serve handler from a table of id-prefix routes.
 *
 * The frame id decodes as UTF-8 and the longest matching prefix wins, so
 * `"tick/spot/"` shadows `"tick/"` regardless of table order. An id no
 * prefix matches throws {@link UnroutedTopicError}, answering the stream
 * with an `Unimplemented` status.
 *
 * ```ts
 * client.serve(router({
 * 	"tick/": route(TickCodec, (tick) => {
 * 		store.applyTick(tick);
 * 		return undefined;
 * 	}),
 * 	"chat/": route(ChatCodec, (message, request) => {
 * 		store.appendChat(message);
 * 		return receipt(request);
 * 	}),
 * }));
 * ```
 */
export function router(
	table: Record<string, Route>,
): (frame: Frame) => Promise<Frame | undefined> {
	const byLongestPrefix = Object.entries(table).sort(
		([left], [right]) => right.length - left.length,
	);

	const dispatch = async (frame: Frame): Promise<Frame | undefined> => {
		const topic = TEXT.decode(frame.id);
		for (const [prefix, entry] of byLongestPrefix) {
			if (topic.startsWith(prefix)) {
				const response = await entry.dispatch(frame);
				return response;
			}
		}

		throw new UnroutedTopicError(topic);
	};
	return dispatch;
}
