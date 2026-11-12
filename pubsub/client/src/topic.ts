/**
 * Topic names and the commands that name them. The page
 * `docs/pubsub-client.md` (Topics) states the rules and their one home.
 */

import type { Engine, Frame, FrameBuilder } from "@wahidgroup/tightbeam-ws-client";

import WIRE from "./wire.generated.json" with { type: "json" };

/**
 * Every reserved command prefix of the rendered contract.
 */
const RESERVED_PREFIXES = Object.values(WIRE.prefixes);

const UTF8 = new TextEncoder();

/**
 * The decoder of each push id. It reads exact UTF-8, so a leading U+FEFF
 * stays part of the name, and it throws on octets that are not UTF-8.
 */
const PUSH_ID = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });

/**
 * The body of a command without a payload: the id is the whole message.
 */
const EMPTY_BODY = new Uint8Array(0);

/**
 * The body of a command: it begins the frame builder of the command, which
 * the command then names, and holds what that body reads until the command
 * settles.
 */
export interface CommandPayload extends Disposable {
	/**
	 * Begin the builder of the frame that carries this body, through `engine`,
	 * for a command that names `topic`.
	 */
	begin(engine: Engine, topic: Topic): FrameBuilder | Promise<FrameBuilder>;
}

/**
 * The body of a `sub/` or `unsub/` command, which holds nothing.
 */
const NO_PAYLOAD: CommandPayload = {
	begin: (engine) => engine.frameBuilder(EMPTY_BODY),
	[Symbol.dispose](): void {
		// A command without a payload holds no handle.
	},
};

/**
 * Builds one {@link Command}. The static block of `Command` assigns it, and
 * only {@link Topic} calls it, so every command names a parsed topic under a
 * prefix of the rendered contract.
 */
let create: (prefix: string, topic: Topic, payload: CommandPayload) => Command;

/**
 * Why the server-side `Topic` validation refuses a name, spelled as the
 * variants of the Rust `TopicError`.
 */
export type TopicErrorCode = "Empty" | "NotUtf8" | "TooLong" | "ReservedPrefix";

/**
 * A name the server-side `Topic` validation refuses. A `TypeError`, so a
 * catch of the base class still matches.
 */
export class TopicError extends TypeError {
	override readonly name = "TopicError";

	constructor(
		/**
		 * The code names the rule that the name breaks.
		 */
		readonly code: TopicErrorCode,
		message: string,
	) {
		super(message);
	}
}

/**
 * A topic name the server-side `Topic` validation accepts.
 *
 * {@link Topic.parse} is the only way to build one, so a `Topic` in hand
 * passed the check before any command frame is built.
 */
export class Topic {
	readonly #name: string;

	private constructor(name: string) {
		this.#name = name;
	}

	/**
	 * The validated name.
	 */
	get name(): string {
		return this.#name;
	}

	/**
	 * Parse `name` under the server-side `Topic` validation. A `Topic`
	 * passes through, because it already passed the check.
	 *
	 * @throws TopicError with code `Empty` for an empty name.
	 * @throws TopicError with code `NotUtf8` for a name with a lone surrogate, which has no UTF-8 form.
	 * @throws TopicError with code `TooLong` for a name past the octet limit of Rust `Topic::MAX_LEN`.
	 * @throws TopicError with code `ReservedPrefix` for a name that starts with a command prefix.
	 */
	static parse(name: Topic | string): Topic {
		if (name instanceof Topic) {
			return name;
		}

		if (name.length === 0) {
			throw new TopicError("Empty", "a topic name must be non-empty");
		}

		// The encoder writes U+FFFD for a lone surrogate, so the server would
		// hold another name than the one the manager routes by.
		if (!name.isWellFormed()) {
			const message = "a topic name must be well-formed UTF-16: it holds a lone surrogate";
			throw new TopicError("NotUtf8", message);
		}

		const octets = UTF8.encode(name).length;
		if (octets > WIRE.topicMaxLen) {
			const message = `a topic name must fit in ${WIRE.topicMaxLen} octets, and this one holds ${octets}`;
			throw new TopicError("TooLong", message);
		}

		for (const prefix of RESERVED_PREFIXES) {
			if (name.startsWith(prefix)) {
				const message = `a topic name must not start with the reserved prefix ${prefix}`;
				throw new TopicError("ReservedPrefix", message);
			}
		}

		const topic = new Topic(name);
		return topic;
	}

	/**
	 * The `sub/` command of this topic.
	 */
	subscribe(): Command {
		const prefix = WIRE.prefixes.subscribe;
		const command = create(prefix, this, NO_PAYLOAD);
		return command;
	}

	/**
	 * The `unsub/` command of this topic.
	 */
	unsubscribe(): Command {
		const prefix = WIRE.prefixes.unsubscribe;
		const command = create(prefix, this, NO_PAYLOAD);
		return command;
	}

	/**
	 * The `pub/` command of this topic, whose frame carries `payload`, freed
	 * as the command settles.
	 */
	publish(payload: CommandPayload): Command {
		const command = create(WIRE.prefixes.publish, this, payload);
		return command;
	}
}

/**
 * The topic `name` parses as, or `undefined` when the validation refuses
 * the name.
 */
function acceptedTopic(name: string): Topic | undefined {
	try {
		const topic = Topic.parse(name);
		return topic;
	} catch (refusal) {
		if (refusal instanceof TopicError) {
			return undefined;
		}

		throw refusal;
	}
}

/**
 * The name that the push id `id` spells in UTF-8, or `undefined` for octets
 * that are not UTF-8.
 */
function spelledName(id: Uint8Array): string | undefined {
	try {
		const name = PUSH_ID.decode(id);
		return name;
	} catch (refusal) {
		if (refusal instanceof TypeError) {
			return undefined;
		}

		throw refusal;
	}
}

/**
 * What the id of one push of the server names, parsed once.
 *
 * - `end`: `end/<topic>`, the completion of `topic`.
 * - `update`: a topic name, an update of that topic.
 */
export interface Push {
	readonly kind: "end" | "update";
	readonly topic: Topic;
}

/**
 * The parse of the id of a push, and its route.
 */
export const Push = {
	/**
	 * The push that the frame id octets `id` name, or `undefined` for an id
	 * that names no topic.
	 */
	parse(id: Uint8Array): Push | undefined {
		const name = spelledName(id);
		if (name === undefined) {
			return undefined;
		}

		const end = WIRE.prefixes.end;
		if (name.startsWith(end)) {
			const completed = acceptedTopic(name.slice(end.length));
			if (completed === undefined) {
				return undefined;
			}

			return { kind: "end", topic: completed };
		}

		const updated = acceptedTopic(name);
		if (updated === undefined) {
			return undefined;
		}

		return { kind: "update", topic: updated };
	},

	/**
	 * Hand `frame`, whose id parsed as `push`, to the receiver of its topic:
	 * the completion of the topic at the order of the frame, or an update.
	 */
	route(
		push: Push,
		receiver: { complete(order: bigint): Promise<void>; receive(update: Frame): Promise<void> },
		frame: Frame,
	): Promise<void> {
		switch (push.kind) {
			case "end":
				return receiver.complete(frame.order);
			case "update":
				return receiver.receive(frame);
		}
	},
};

/**
 * One command a client sends: a prefix of the rendered contract and the topic
 * it names.
 *
 * - {@link Topic.subscribe}, {@link Topic.unsubscribe}, and {@link Topic.publish} build each one.
 * - The constructor is private, so every command carries a prefix of the contract.
 */
export class Command implements Disposable {
	/**
	 * The topic the command names.
	 */
	readonly topic: Topic;

	readonly #prefix: string;

	/**
	 * The body, whose hold {@link [Symbol.dispose]} frees as the command
	 * settles.
	 */
	readonly #payload: CommandPayload;

	static {
		create = (prefix, topic, payload): Command => {
			const command = new Command(prefix, topic, payload);
			return command;
		};
	}

	private constructor(prefix: string, topic: Topic, payload: CommandPayload) {
		this.#prefix = prefix;
		this.topic = topic;
		this.#payload = payload;
	}

	/**
	 * The frame id of the command: its prefix, then its topic name.
	 */
	get id(): string {
		const id = `${this.#prefix}${this.topic.name}`;
		return id;
	}

	/**
	 * Build the frame of the command through the builder of `engine`.
	 */
	async frame(engine: Engine): Promise<Frame> {
		const begun = await this.#payload.begin(engine, this.topic);
		const built = await begun.withId(this.id).build();
		return built;
	}

	/**
	 * Free what the body holds, once the command settles: acknowledged,
	 * refused, or dropped with its lane. A deferred command still holds it,
	 * because its replay builds the frame again.
	 */
	[Symbol.dispose](): void {
		this.#payload[Symbol.dispose]();
	}
}
