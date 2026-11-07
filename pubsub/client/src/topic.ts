/**
 * Topic names and the commands that name them.
 *
 * The wire constants have one home, Rust `Topic`. Its `wire_contract`
 * example renders the octet limit and the command prefixes into
 * `wire.generated.json`, which `make -C pubsub client` writes before `tsc`
 * compiles this package. A topic is non-empty, fits in that limit of UTF-8
 * octets, matches exactly, and starts outside the reserved command prefixes,
 * so topics and commands stay distinct.
 */

import type {
	Engine,
	Frame,
	FrameBuilder,
} from "@wahidgroup/tightbeam-ws-client";

import WIRE from "./wire.generated.json" with { type: "json" };

/**
 * Every reserved command prefix of the wire contract.
 */
const RESERVED_PREFIXES = Object.values(WIRE.prefixes);

const UTF8 = new TextEncoder();

/**
 * The body of a command without a payload: the id is the whole message.
 */
const EMPTY_BODY = new Uint8Array(0);

/**
 * Builds the frame of a command from a builder that already carries the
 * command id.
 */
export type CommandBody = (command: FrameBuilder) => Promise<Frame>;

/**
 * The body of a `sub/`, `unsub/`, or `end/` command.
 */
const NO_PAYLOAD: CommandBody = (command) => {
	const empty = command.withMessage(EMPTY_BODY);
	const built = empty.build();
	return built;
};

/**
 * What a command holds for its body and frees as it settles: nothing for a
 * command without a payload.
 */
const NOTHING_HELD: Disposable = {
	[Symbol.dispose](): void {
		// A command without a payload holds no handle.
	},
};

/**
 * Builds one {@link Command}. The static block of `Command` assigns it, and
 * only {@link Topic} and {@link Command.parse} call it, so every command
 * names a parsed topic under a prefix of the wire contract.
 */
let mint: (
	prefix: string,
	topic: Topic,
	body: CommandBody,
	held: Disposable,
) => Command;

/**
 * Why the server-side `Topic` validation refuses a name, spelled as the
 * variants of the Rust `TopicError`.
 */
export type TopicErrorCode = "Empty" | "TooLong" | "ReservedPrefix";

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
	private constructor(
		/**
		 * The validated name.
		 */
		readonly name: string,
	) {}

	/**
	 * Parse `name` under the server-side `Topic` validation. A `Topic`
	 * passes through, because it already passed the check.
	 *
	 * @throws TopicError with code `Empty` for an empty name, `TooLong` for
	 * a name past the octet limit of Rust `Topic::MAX_LEN`, and
	 * `ReservedPrefix` for a name that starts with a command prefix.
	 */
	static parse(name: Topic | string): Topic {
		if (name instanceof Topic) {
			return name;
		}

		if (name.length === 0) {
			throw new TopicError("Empty", "a topic name must be non-empty");
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
		const command = mint(prefix, this, NO_PAYLOAD, NOTHING_HELD);
		return command;
	}

	/**
	 * The `unsub/` command of this topic.
	 */
	unsubscribe(): Command {
		const prefix = WIRE.prefixes.unsubscribe;
		const command = mint(prefix, this, NO_PAYLOAD, NOTHING_HELD);
		return command;
	}

	/**
	 * The `pub/` command of this topic, whose frame `body` builds over what
	 * `held` holds, freed as the command settles.
	 */
	publish(body: CommandBody, held: Disposable): Command {
		const command = mint(WIRE.prefixes.publish, this, body, held);
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
 * One wire command: a prefix of the wire contract and the topic it names.
 *
 * {@link Topic.subscribe}, {@link Topic.unsubscribe}, and
 * {@link Topic.publish} build the commands a client sends, and
 * {@link Command.parse} reads the id of one the server sends. The
 * constructor is private, so no command carries a hand-built prefix.
 */
export class Command implements Disposable {
	/**
	 * The topic the command names.
	 */
	readonly topic: Topic;

	readonly #prefix: string;

	readonly #body: CommandBody;

	/**
	 * What the body holds, which {@link [Symbol.dispose]} frees as the command
	 * settles.
	 */
	readonly #held: Disposable;

	static {
		mint = (prefix, topic, body, held): Command => {
			const command = new Command(prefix, topic, body, held);
			return command;
		};
	}

	private constructor(
		prefix: string,
		topic: Topic,
		body: CommandBody,
		held: Disposable,
	) {
		this.#prefix = prefix;
		this.topic = topic;
		this.#body = body;
		this.#held = held;
	}

	/**
	 * Parse the frame id `id` as a command: a reserved prefix, then a valid
	 * topic name. Every other id answers `undefined`, such as the id of a
	 * topic update. A parsed command carries no payload.
	 */
	static parse(id: string): Command | undefined {
		const opens = (reserved: string): boolean => id.startsWith(reserved);
		const prefix = RESERVED_PREFIXES.find(opens);
		if (prefix === undefined) {
			return undefined;
		}

		const name = id.slice(prefix.length);
		const topic = acceptedTopic(name);
		if (topic === undefined) {
			return undefined;
		}

		const command = mint(prefix, topic, NO_PAYLOAD, NOTHING_HELD);
		return command;
	}

	/**
	 * The frame id of the command: its prefix, then its topic name.
	 */
	get id(): string {
		const id = `${this.#prefix}${this.topic.name}`;
		return id;
	}

	/**
	 * The topic an `end/` command completes, which the server sends when it
	 * quiesces. Each command a client sends answers `undefined`.
	 */
	get completed(): Topic | undefined {
		if (this.#prefix === WIRE.prefixes.end) {
			return this.topic;
		}

		return undefined;
	}

	/**
	 * Build the frame of the command through the builder of `engine`.
	 */
	frame(engine: Engine): Promise<Frame> {
		const named = engine.frameBuilder().withId(this.id);
		const built = this.#body(named);
		return built;
	}

	/**
	 * Free what the body holds, once the command settles: acknowledged,
	 * refused, or dropped with its lane. A deferred command still holds it,
	 * because its replay builds the frame again.
	 */
	[Symbol.dispose](): void {
		this.#held[Symbol.dispose]();
	}
}
