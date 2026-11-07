/**
 * Client-side subscription lifecycle over a multiplexed tightbeam
 * connection.
 *
 * # Ports
 *
 * {@link ClientPorts.split} splits a client once into its
 * {@link CommandPort} and its {@link ServePort}. The `Engine` that dialed the
 * client builds and decodes the frames of both. The manager claims the serve
 * port exclusively, so a later `client.serve` throws instead of silently
 * unrouting updates. Updates dispatch by exact topic match, `end/<topic>`
 * completes a subscription, and every other stream goes to the application's
 * own {@link ManagerOptions.fallback} (or answers `Unimplemented`).
 *
 * # Commands
 *
 * Every command leaves through the {@link CommandLane} of its topic, the one
 * holder of the command port. Subscribing sends `sub/<topic>`, which the
 * server's `Ok` acknowledges. Publishing sends `pub/<topic>` with the encoded
 * message, answered by servers that enable client publish.
 */

import type {
	Engine,
	Envelope,
	Frame,
	FrameBuilder,
	MessageCodec,
	MuxStreamHandler,
	ServeOptions,
} from "@wahidgroup/tightbeam-ws-client";
import {
	ClientTransportError,
	HeldCodec,
	UnroutedTopicError,
} from "@wahidgroup/tightbeam-ws-client";

import { PullChannel } from "./channel.js";
import { TopicGate } from "./gate.js";
import type { CommandBody } from "./topic.js";
import { Command, Topic } from "./topic.js";

const TEXT = new TextDecoder();

/**
 * One decoded update: the typed message, the frame it rode in on, and
 * the topic that routed it.
 */
export interface Update<T> {
	readonly message: T;
	readonly frame: Frame;
	readonly topic: string;
}

/**
 * Receives one decoded update. The manager awaits the result before
 * acknowledging the stream, so a slow handler back-pressures the
 * server's delivery lane instead of piling up.
 */
export type UpdateHandler<T> = (
	message: T,
	frame: Frame,
	topic: string,
) => void | Promise<void>;

/**
 * Observes a detected gap: updates between `expected` and `received`
 * were dropped (delivery policy) for this subscriber. The update that
 * revealed the gap is still delivered, even when the observer throws:
 * the failure surfaces only after the delivery settles. When omitted,
 * the manager re-emits the `sub/` command before that delivery, so a
 * replay-capable server can fill the gap first.
 */
export type GapHandler = (
	topic: string,
	expected: bigint,
	received: bigint,
) => void | Promise<void>;

/**
 * Observes topic completion: the server pushed `end/<topic>` (quiesce).
 * The subscription is already removed when this fires.
 */
export type EndHandler = (topic: string) => void;

/**
 * The optional observers every subscription takes. With
 * {@link onUpdate} omitted, updates arrive through the one iterator of the
 * returned {@link IteratingSubscription} instead.
 */
export interface SubscriptionObservers<T> {
	readonly onUpdate?: UpdateHandler<T>;
	readonly onGap?: GapHandler;
	readonly onEnd?: EndHandler;
}

/**
 * How a topic's payload rides a frame, in exactly one of two shapes:
 *
 * - `codec`: the frame body is the message under a {@link MessageCodec}.
 * - `envelope`: the frame body carries a full inner frame, built and
 *   unwrapped (verified, opened, inflated, decoded) under the
 *   {@link Envelope}'s declared layers.
 */
export type PayloadSource<T> =
	| {
			readonly codec: MessageCodec<T>;
			readonly envelope?: undefined;
	  }
	| {
			readonly envelope: Envelope<T>;
			readonly codec?: undefined;
	  };

/**
 * Everything one subscription needs: how updates decode, plus the
 * observers.
 */
export type SubscribeOptions<T> = SubscriptionObservers<T> & PayloadSource<T>;

/**
 * A topic payload: how a message builds into a command frame on publish,
 * and how an update frame decodes into a message on delivery.
 *
 * The two kinds are the codec and the envelope of {@link PayloadSource}.
 * {@link PayloadShape.of} is the one decider: it picks the kind, and for a
 * codec whether the shape decodes or builds, so no other step asks which
 * kind it holds.
 */
export interface PayloadShape<T> extends Disposable {
	/**
	 * Build the frame that carries `message` from `command`, the builder
	 * that already names the command.
	 */
	build(command: FrameBuilder, message: T): Promise<Frame>;

	/**
	 * Decode the message an update frame carries.
	 */
	decode(update: Frame): T | Promise<T>;
}

/**
 * The codec kind: the body is the message under a codec.
 *
 * A subscription only decodes, so its shape holds the caller's codec and
 * reads no handle of it. A publish builds its frame at the turn of its
 * command, possibly after a reconnect, so its shape holds the codec under a
 * copy of its content type and frees the copy as the command settles.
 */
class CodecShape<T> implements PayloadShape<T> {
	private readonly codec: MessageCodec<T>;

	/**
	 * The copy a publish holds, which the disposal frees.
	 */
	readonly #held: HeldCodec<T> | undefined;

	private constructor(codec: MessageCodec<T>, held?: HeldCodec<T>) {
		this.codec = codec;
		this.#held = held;
	}

	/**
	 * The shape that decodes under `codec`, which it holds as the caller
	 * passed it.
	 */
	static decoding<T>(codec: MessageCodec<T>): CodecShape<T> {
		const shape = new CodecShape(codec);
		return shape;
	}

	/**
	 * The shape that builds under a copy of `codec`, freed by the disposal.
	 */
	static building<T>(codec: MessageCodec<T>): CodecShape<T> {
		const held = HeldCodec.of(codec);
		const shape = new CodecShape(held, held);
		return shape;
	}

	build(command: FrameBuilder, message: T): Promise<Frame> {
		const built = command.withMessage(this.codec, message).build();
		return built;
	}

	decode(update: Frame): T {
		const message = update.message(this.codec);
		return message;
	}

	/**
	 * Free the copy a publish holds. A decoding shape holds none.
	 */
	[Symbol.dispose](): void {
		this.#held?.[Symbol.dispose]();
	}
}

/**
 * The envelope kind: the body is a full inner frame under the envelope's
 * declared layers, which the registry relays byte-for-byte. The `framed`
 * codec of the engine carries the inner frame.
 */
class EnvelopeShape<T> implements PayloadShape<T> {
	constructor(
		private readonly envelope: Envelope<T>,
		private readonly framed: MessageCodec<Frame>,
	) {}

	async build(command: FrameBuilder, message: T): Promise<Frame> {
		const inner = await this.envelope.frame(message).build();
		const built = await command.withMessage(this.framed, inner).build();
		return built;
	}

	decode(update: Frame): Promise<T> {
		const inner = update.message(this.framed);
		const message = this.envelope.unwrap(inner);
		return message;
	}

	/**
	 * Nothing to free: the envelope holds its own copies.
	 */
	[Symbol.dispose](): void {
		// The envelope keeps the copies it took for as long as it lives.
	}
}

/**
 * What a payload shape serves: the updates a subscription decodes, or the
 * commands a publish builds.
 */
export type ShapeUse = "decoding" | "building";

/**
 * The ways to make a {@link PayloadShape}.
 */
export const PayloadShape = {
	/**
	 * The shape `source` names for `use`, whose frames `engine` builds and
	 * decodes. A building codec shape holds a copy of every handle it reads
	 * at the turn of its command, freed by its disposal.
	 */
	of<T>(
		source: PayloadSource<T>,
		engine: Engine,
		use: ShapeUse,
	): PayloadShape<T> {
		if (source.envelope !== undefined) {
			const shape = new EnvelopeShape(source.envelope, engine.framed);
			return shape;
		}
		if (use === "decoding") {
			const shape = CodecShape.decoding(source.codec);
			return shape;
		}

		const shape = CodecShape.building(source.codec);
		return shape;
	},
};

/**
 * Where one subscription stands.
 *
 * - `pending`: its `sub/` command awaits its turn or the acknowledgment.
 * - `live`: the server acknowledged the `sub/` command.
 * - `deferred`: the connection was lost, and {@link SubscriptionManager.reattach} replays the subscription.
 * - `ended`: unsubscribed, refused, or completed by the server.
 */
export type SubscriptionState = "pending" | "live" | "deferred" | "ended";

/**
 * Why the manager refuses a subscription call: `AlreadySubscribed` for a
 * second subscribe to a live topic, `AlreadyIterating` for a second iterator
 * over one {@link IteratingSubscription}, `Disposed` for a subscribe, a
 * publish, or a reattach on a disposed manager, and `DeferralFull` for a
 * command that a lost connection would defer past the {@link MAX_DEFERRED}
 * commands that one manager keeps across its topics.
 */
export type SubscriptionErrorCode =
	"AlreadySubscribed" | "AlreadyIterating" | "Disposed" | "DeferralFull";

/**
 * The most commands that the lanes of one manager keep, across every topic,
 * for a lost connection. A command past the budget refuses with
 * `DeferralFull`, so an outage holds bounded memory however many topics it
 * spans (CWE-770).
 */
export const MAX_DEFERRED = 256;

/**
 * The deferral budget of one manager: the slots of {@link MAX_DEFERRED} that
 * its lanes hold. A lane draws a slot as it defers a command, and returns it
 * as the command leaves its queue: on a replay, or on a drop.
 */
export class DeferralBudget {
	#held = 0;

	/**
	 * Take one slot, or answer `false` when every slot is held.
	 */
	draw(): boolean {
		if (this.#held >= MAX_DEFERRED) {
			return false;
		}

		this.#held += 1;
		return true;
	}

	/**
	 * Return the `count` slots of commands that left a queue.
	 */
	refund(count: number): void {
		this.#held -= count;
	}
}

/**
 * A subscription call the manager refuses, with the rule it breaks.
 */
export class SubscriptionError extends Error {
	override readonly name = "SubscriptionError";

	constructor(
		/**
		 * The code names the rule that the call breaks.
		 */
		readonly code: SubscriptionErrorCode,
		message: string,
	) {
		super(message);
	}
}

/**
 * The handle of a subscription that delivers through its `onUpdate`
 * handler: its topic, its state, and its unsubscribe. The type holds no
 * iterator, so the compiler refuses a `for await` over a handler
 * subscription.
 */
export interface HandlerSubscription {
	/**
	 * The topic name the subscription dispatches.
	 */
	readonly topic: string;

	/**
	 * Where the subscription stands right now.
	 */
	readonly state: SubscriptionState;

	/**
	 * Emit `unsub/<topic>` and stop dispatching the topic locally.
	 *
	 * Once this subscription has ended, the call returns at once and leaves
	 * a newer subscription to the same topic live.
	 */
	unsubscribe(): Promise<void>;
}

/**
 * The handle of a subscription without an `onUpdate` handler: the members
 * of a {@link HandlerSubscription}, plus the one iterator that delivers
 * each update.
 *
 * ```ts
 * const prices = await manager.subscribe("prices", { codec: engine.opaque });
 * for await (const { message, frame } of prices) {
 *     render(message, frame.order);
 * }
 * ```
 *
 * Iteration ends when the topic completes or unsubscribes, and a `break`
 * out of the loop unsubscribes the topic.
 */
export interface IteratingSubscription<T>
	extends HandlerSubscription, AsyncIterable<Update<T>> {
	/**
	 * The one iterator of the subscription. Its `return`, which a `break`
	 * calls, unsubscribes the topic.
	 *
	 * @throws SubscriptionError with code `AlreadyIterating` on a second
	 * call.
	 */
	[Symbol.asyncIterator](): AsyncIterator<Update<T>>;
}

/**
 * Manager construction options.
 */
export interface ManagerOptions {
	/**
	 * Receives server-initiated streams no subscription matches. When
	 * omitted, unmatched streams answer `Unimplemented`.
	 */
	readonly fallback?: MuxStreamHandler;
}

/**
 * The command half of a client: the call that sends one command stream.
 */
export interface CommandPort {
	/**
	 * Send `command` on a fresh stream, and resolve with the answer of the
	 * server.
	 */
	emit(command: Frame): Promise<Frame | undefined>;
}

/**
 * The serve half of a client: the call that claims the streams the server
 * initiates, and the engine that dialed the client.
 */
export interface ServePort {
	/**
	 * The engine that dialed the client, which builds the command frames and
	 * decodes what the server sends.
	 */
	readonly engine: Engine;

	/**
	 * Serve every server-initiated stream with `handler`.
	 */
	serve(handler: MuxStreamHandler, options?: ServeOptions): void;
}

/**
 * The subscription a `sub/` command speaks for. Its {@link CommandLane}
 * decides each outcome once and tells the subscriber, which moves its own
 * state.
 */
export interface Subscriber {
	/**
	 * Whether the command still leaves at its turn.
	 */
	wants(): boolean;

	/**
	 * Answer the command leaving on the connection of the lane.
	 */
	leaving(): void;

	/**
	 * Answer the acknowledgment of the server.
	 */
	acknowledged(): void;

	/**
	 * Answer a lost connection. The lane keeps the command for the lane
	 * that replaces it.
	 */
	deferred(): void;

	/**
	 * Answer the refusal of the server.
	 */
	refused(): void;

	/**
	 * Answer whether the subscription was live on the lost connection. A
	 * lapsed subscription replays its `sub/` before the deferred commands,
	 * because it was acknowledged before any of them was sent.
	 */
	lapse(): boolean;
}

/**
 * A command that a lost connection deferred, with the subscriber it speaks
 * for.
 */
interface Deferred {
	readonly command: Command;
	readonly subscriber: Subscriber | undefined;
}

/**
 * Settle once `pending` settles, whether it resolves or rejects.
 */
async function whenSettled(pending: Promise<unknown>): Promise<void> {
	try {
		await pending;
	} catch {
		// The sender of the command receives its failure.
	}
}

/**
 * The one path of the commands for one topic over one connection.
 *
 * - Each command leaves once the command before it settled, so the server
 *   applies them in the order they were sent. Two command streams of one
 *   connection may otherwise reach the server's handlers in either order.
 * - The lane decides the loss once: a command the lost connection refuses
 *   with `ConnectionClosed` settles, and the lane keeps it.
 * - {@link CommandLane.adopt} replays the commands that the lane of the
 *   lost connection kept, before any command sent after it.
 */
export class CommandLane implements AsyncDisposable {
	/**
	 * The topic every command of the lane names.
	 */
	readonly topic: Topic;

	readonly #port: CommandPort;

	/**
	 * The engine that builds the frame of each command.
	 */
	readonly #engine: Engine;

	/**
	 * The last turn of the lane, settled either way.
	 */
	#tail: Promise<void> = Promise.resolve();

	/**
	 * The turns that have not settled yet.
	 */
	#queued = 0;

	/**
	 * The commands the lost connection deferred, in the order they were
	 * sent.
	 */
	readonly #deferred: Deferred[] = [];

	/**
	 * The deferral budget of the manager, which every lane of it shares.
	 */
	readonly #budget: DeferralBudget;

	constructor(
		topic: Topic,
		port: CommandPort,
		engine: Engine,
		budget: DeferralBudget,
	) {
		this.topic = topic;
		this.#port = port;
		this.#engine = engine;
		this.#budget = budget;
	}

	/**
	 * Whether the lane holds no turn and no deferred command.
	 */
	get idle(): boolean {
		const idle = this.#queued === 0 && this.#deferred.length === 0;
		return idle;
	}

	/**
	 * Send `command` at its turn, while `subscriber` still wants it, and
	 * tell `subscriber` the outcome.
	 *
	 * Resolves once the server acknowledges the command, or once the lost
	 * connection defers it.
	 *
	 * @throws The refusal of the server.
	 */
	send(command: Command, subscriber?: Subscriber): Promise<void> {
		const turn = (): Promise<void> => this.#turn(command, subscriber);
		const sent = this.#after(turn);
		return sent;
	}

	/**
	 * Replay the commands that `lost`, the lane of the lost connection,
	 * deferred, as the first turn of this lane.
	 *
	 * The replay waits for `lost` to settle. A lapsed `subscriber` then
	 * replays its `sub/` first, and the deferred commands follow in the
	 * order they were sent.
	 *
	 * Resolves with the refusal of each replayed command the server
	 * refused.
	 */
	adopt(
		lost: CommandLane | undefined,
		subscriber: Subscriber | undefined,
	): Promise<unknown[]> {
		const run = (): Promise<unknown[]> => this.#replay(lost, subscriber);
		const replayed = this.#after(run);
		return replayed;
	}

	/**
	 * Run `turn` once the turn before it settles.
	 */
	#after<R>(turn: () => Promise<R>): Promise<R> {
		const previous = this.#tail;
		const run = async (): Promise<R> => {
			await previous;
			try {
				const ran = await turn();
				return ran;
			} finally {
				this.#queued -= 1;
			}
		};

		this.#queued += 1;
		const running = run();
		this.#tail = whenSettled(running);
		return running;
	}

	/**
	 * Replay the deferred commands of `lost` through this lane, after the
	 * `sub/` of a lapsed `subscriber`.
	 */
	async #replay(
		lost: CommandLane | undefined,
		subscriber: Subscriber | undefined,
	): Promise<unknown[]> {
		const replays: Deferred[] = [];
		if (lost !== undefined) {
			await lost.#tail;
			const deferred = lost.#deferred.splice(0);
			this.#budget.refund(deferred.length);
			replays.push(...deferred);
		}

		if (subscriber?.lapse() === true) {
			const resubscribing = this.topic.subscribe();
			replays.unshift({ command: resubscribing, subscriber });
		}

		const refusals: unknown[] = [];
		for (const replay of replays) {
			try {
				await this.#turn(replay.command, replay.subscriber);
			} catch (refusal) {
				refusals.push(refusal);
			}
		}

		return refusals;
	}

	/**
	 * Send `command` while `subscriber` wants it, then tell `subscriber` the
	 * outcome. A lost connection defers the command, and a refusal throws.
	 */
	async #turn(command: Command, subscriber?: Subscriber): Promise<void> {
		let deferred = false;
		try {
			deferred = await this.#settle(command, subscriber);
		} finally {
			// A deferred command builds its frame again at its replay, so it
			// keeps what its body holds. Every other outcome settles it.
			if (!deferred) {
				command[Symbol.dispose]();
			}
		}
	}

	/**
	 * Send `command` while `subscriber` wants it, then tell `subscriber` the
	 * outcome. Answers whether the lost connection deferred the command.
	 */
	async #settle(command: Command, subscriber?: Subscriber): Promise<boolean> {
		const frame = await command.frame(this.#engine);
		const wanted = subscriber?.wants() ?? true;
		if (!wanted) {
			return false;
		}

		subscriber?.leaving();

		try {
			await this.#port.emit(frame);
		} catch (failure) {
			if (!ClientTransportError.isConnectionClosed(failure)) {
				subscriber?.refused();
				throw failure;
			}

			const slot = this.#budget.draw();
			if (!slot) {
				subscriber?.refused();
				const message = `the manager already holds ${MAX_DEFERRED} deferred commands`;
				throw new SubscriptionError("DeferralFull", message);
			}

			this.#deferred.push({ command, subscriber });
			subscriber?.deferred();
			return true;
		}

		subscriber?.acknowledged();
		return false;
	}

	/**
	 * Wait for the turns in flight, then drop the commands the lost
	 * connection deferred, which no replay will send, and free what each one
	 * holds. A command that defers while the disposal waits drops with the
	 * rest.
	 *
	 * An emit has no deadline of its own, so the wait ends as each command
	 * settles: the server answers it, or the client closes, which settles
	 * every pending emit with `ConnectionClosed`.
	 */
	async [Symbol.asyncDispose](): Promise<void> {
		await this.#tail;

		const dropped = this.#deferred.splice(0);
		this.#budget.refund(dropped.length);
		for (const { command } of dropped) {
			command[Symbol.dispose]();
		}
	}
}

/**
 * A client split once into the uses the manager makes of it.
 *
 * The command port sits in a private field, which only
 * {@link ClientPorts.lane} reads, so every command the manager sends passes
 * a {@link CommandLane}. The manager reaches the {@link ServePort} alone,
 * which holds no `emit`, and through it the engine that dialed the client.
 */
export class ClientPorts {
	/**
	 * The serve half of the client.
	 */
	readonly serving: ServePort;

	readonly #commands: CommandPort;

	private constructor(commands: CommandPort, serving: ServePort) {
		this.#commands = commands;
		this.serving = serving;
	}

	/**
	 * Split `client` into its command port and its serve port. This is the
	 * one site that holds the whole client.
	 */
	static split(client: CommandPort & ServePort): ClientPorts {
		const ports = new ClientPorts(client, client);
		return ports;
	}

	/**
	 * The engine that dialed the client, which builds the command frames and
	 * decodes the payloads of the client.
	 */
	get engine(): Engine {
		return this.serving.engine;
	}

	/**
	 * A new lane for the commands of `topic`, over the command port, which
	 * defers into `budget`, the budget of the manager.
	 */
	lane(topic: Topic, budget: DeferralBudget): CommandLane {
		const commands = this.#commands;
		const lane = new CommandLane(topic, commands, this.engine, budget);
		return lane;
	}
}

/**
 * A failure held until a later step settles. The wrapper keeps a thrown
 * `undefined` apart from no failure.
 */
interface HeldFailure {
	readonly cause: unknown;
}

/**
 * How a subscription ends.
 *
 * - `unsubscribed`: the application unsubscribed.
 * - `refused`: the server refused its `sub/`, on subscribe or on reattach.
 * - `completed`: the server pushed `end/<topic>`.
 */
export type Ending = "unsubscribed" | "refused" | "completed";

/**
 * How an entry hands each update to the application. The two kinds are
 * {@link HandlerDelivery} and {@link ChannelDelivery}, and
 * {@link Delivery.of} picks one from the subscribe options.
 */
export interface Delivery {
	/**
	 * Decode `update` and hand it over while `live` holds.
	 */
	deliver(update: Frame, live: () => boolean): Promise<void>;

	/**
	 * End the delivery with its subscription.
	 */
	end(): void;
}

/**
 * The handler kind: each update goes to the `onUpdate` handler.
 */
export class HandlerDelivery<T> implements Delivery {
	constructor(
		private readonly topic: Topic,
		private readonly shape: PayloadShape<T>,
		private readonly onUpdate: UpdateHandler<T>,
	) {}

	async deliver(update: Frame, live: () => boolean): Promise<void> {
		const message = await this.shape.decode(update);
		if (!live()) {
			return;
		}

		await this.onUpdate(message, update, this.topic.name);
	}

	end(): void {
		// Each update reaches the handler as it arrives, so no queue waits.
	}

	/**
	 * The handle of `entry`, which `release` unsubscribes.
	 */
	handle(entry: Entry, release: () => Promise<void>): HandlerSubscription {
		const subscription: HandlerSubscription = {
			topic: this.topic.name,
			get state(): SubscriptionState {
				return entry.state;
			},
			unsubscribe: release,
		};
		return subscription;
	}
}

/**
 * The iterator kind: each update parks on the pull channel until the one
 * iterator takes it, so iteration back-pressures the server exactly like a
 * slow handler.
 */
export class ChannelDelivery<T> implements Delivery {
	private readonly channel = new PullChannel<Update<T>>();

	/**
	 * Whether the one iterator was handed out.
	 */
	private iterated = false;

	constructor(
		private readonly topic: Topic,
		private readonly shape: PayloadShape<T>,
	) {}

	async deliver(update: Frame, live: () => boolean): Promise<void> {
		const message = await this.shape.decode(update);
		if (!live()) {
			return;
		}

		const pulled: Update<T> = {
			message,
			frame: update,
			topic: this.topic.name,
		};
		await this.channel.put(pulled);
	}

	end(): void {
		this.channel.finish();
	}

	/**
	 * The handle of `entry`, which `release` unsubscribes.
	 */
	handle(
		entry: Entry,
		release: () => Promise<void>,
	): IteratingSubscription<T> {
		const iterate = (): AsyncIterator<Update<T>> => this.iterator(release);
		const subscription: IteratingSubscription<T> = {
			topic: this.topic.name,
			get state(): SubscriptionState {
				return entry.state;
			},
			unsubscribe: release,
			[Symbol.asyncIterator]: iterate,
		};
		return subscription;
	}

	/**
	 * The one iterator over the channel. Its `return` runs `release`.
	 */
	private iterator(release: () => Promise<void>): AsyncIterator<Update<T>> {
		if (this.iterated) {
			const message =
				"a subscription has one iterator: keep the first one, or subscribe again";
			throw new SubscriptionError("AlreadyIterating", message);
		}

		this.iterated = true;
		const iterator: AsyncIterator<Update<T>> = {
			next: (): Promise<IteratorResult<Update<T>>> => this.channel.next(),
			return: async (): Promise<IteratorResult<Update<T>>> => {
				await release();
				const done: IteratorResult<Update<T>> = {
					value: undefined,
					done: true,
				};
				return done;
			},
		};
		return iterator;
	}
}

/**
 * The ways to make a {@link Delivery}.
 */
export const Delivery = {
	/**
	 * The delivery `options` names for `topic`: its `onUpdate` handler, or
	 * the one iterator of a subscription without one. `engine` decodes each
	 * update.
	 */
	of<T>(
		topic: Topic,
		options: SubscribeOptions<T>,
		engine: Engine,
	): HandlerDelivery<T> | ChannelDelivery<T> {
		const shape = PayloadShape.of(options, engine, "decoding");
		const onUpdate = options.onUpdate;
		if (onUpdate !== undefined) {
			const delivery = new HandlerDelivery(topic, shape, onUpdate);
			return delivery;
		}

		const delivery = new ChannelDelivery(topic, shape);
		return delivery;
	},
};

/**
 * The dispatch record of one subscription while its topic stays desired.
 *
 * {@link Entries.end} ends an entry in the same step that removes it from
 * the map, so an entry is open exactly while it holds its topic. That is the
 * unsubscribe fence: the delivery path re-checks it after every await, so
 * in-flight work respects unsubscribe and completion.
 *
 * Against {@link TopicGate}, classify before delivery. Advance after
 * delivery while the entry stays open, so a failed decode or handler leaves
 * the stamp free for a later gap.
 *
 * The state moves only through the {@link Subscriber} answers and
 * {@link end}, and an ended entry stays ended.
 */
export class Entry implements Subscriber {
	private readonly gate = new TopicGate();

	/**
	 * The topic this entry dispatches.
	 */
	readonly topic: Topic;

	private readonly delivery: Delivery;

	private readonly onGap: GapHandler | undefined;

	private readonly onEnd: EndHandler | undefined;

	private readonly entries: Entries;

	private mode: SubscriptionState = "pending";

	/**
	 * Whether a `sub/` of the entry has left.
	 */
	private subscribed = false;

	constructor(
		topic: Topic,
		delivery: Delivery,
		observers: Pick<SubscriptionObservers<unknown>, "onEnd" | "onGap">,
		entries: Entries,
	) {
		this.topic = topic;
		this.delivery = delivery;
		this.onGap = observers.onGap;
		this.onEnd = observers.onEnd;
		this.entries = entries;
	}

	/**
	 * Where the subscription stands.
	 */
	get state(): SubscriptionState {
		return this.mode;
	}

	/**
	 * Whether the entry still holds its topic.
	 */
	private get open(): boolean {
		const open = this.mode !== "ended";
		return open;
	}

	/**
	 * Receive one update: classify it against the gate, answer a gap it
	 * reveals, deliver it, then commit its stamp while the entry stays open.
	 *
	 * Without a gap observer, `resync` answers the gap before the delivery,
	 * so a replay-capable server fills it while the gate still expects the
	 * missing stamps. A gap observer answers in its place. The revealing
	 * update delivers even when the answer fails, and that failure throws
	 * once the delivery settles. A failed delivery throws in its place.
	 */
	async receive(update: Frame, resync: () => Promise<void>): Promise<void> {
		const order = update.order;
		const expected = this.gate.expected;
		const verdict = this.gate.classify(order);
		if (verdict === "stale") {
			return;
		}

		let answered: HeldFailure | undefined;
		if (verdict === "gap" && expected !== undefined) {
			answered = await this.answerGap(expected, order, resync);
		}

		const delivered = await this.deliverWhileOpen(update);
		const failure = delivered ?? answered;
		if (failure !== undefined) {
			throw failure.cause;
		}
	}

	/**
	 * Answer the gap from `expected` to `received`: hand it to the gap
	 * observer, or run `resync` without one. The failure of either is held,
	 * so the revealing update still delivers.
	 */
	private async answerGap(
		expected: bigint,
		received: bigint,
		resync: () => Promise<void>,
	): Promise<HeldFailure | undefined> {
		try {
			if (this.onGap === undefined) {
				await resync();
			} else {
				await this.onGap(this.topic.name, expected, received);
			}
		} catch (cause) {
			const failure = { cause };
			return failure;
		}

		return undefined;
	}

	/**
	 * Deliver `update` while the entry stays open, then commit its stamp. A
	 * failed delivery witnesses the stamp instead, so the next update reveals
	 * the loss as a gap even before any baseline.
	 */
	private async deliverWhileOpen(
		update: Frame,
	): Promise<HeldFailure | undefined> {
		if (!this.open) {
			return undefined;
		}

		const live = (): boolean => this.open;
		try {
			await this.delivery.deliver(update, live);
		} catch (cause) {
			this.gate.witness(update.order);
			const failure = { cause };
			return failure;
		}

		/*
		 * The entry may have ended by the time the delivery path returns.
		 */
		if (this.open) {
			this.gate.advance(update.order);
		}

		return undefined;
	}

	/**
	 * The first `sub/` of the entry always leaves, so the server answers the
	 * subscribe call. Each later one, a resync or a replay, leaves while the
	 * entry holds its topic.
	 */
	wants(): boolean {
		const wanted = !this.subscribed || this.open;
		return wanted;
	}

	/**
	 * A `sub/` leaves, and a deferred subscription is pending again.
	 */
	leaving(): void {
		this.subscribed = true;
		if (this.mode === "deferred") {
			this.mode = "pending";
		}
	}

	/**
	 * The server acknowledged `sub/`: a pending subscription goes live.
	 */
	acknowledged(): void {
		if (this.mode === "pending") {
			this.mode = "live";
		}
	}

	/**
	 * The connection lost a `sub/`: a pending subscription waits for the
	 * replay. A live one keeps its acknowledgment until {@link lapse}.
	 */
	deferred(): void {
		if (this.mode === "pending") {
			this.mode = "deferred";
		}
	}

	/**
	 * The server refused `sub/`: a pending subscription ends. A live one
	 * stays live, because the refusal answered a gap resync.
	 */
	refused(): void {
		if (this.mode === "pending") {
			this.entries.end(this, "refused");
		}
	}

	/**
	 * A live subscription lapses with its lost connection: it waits for the
	 * replay, and its gate resets, so the next update re-baselines. Answers
	 * whether it lapsed.
	 */
	lapse(): boolean {
		if (this.mode !== "live") {
			return false;
		}

		this.gate.reset();
		this.mode = "deferred";
		return true;
	}

	/**
	 * End the subscription and its delivery. A completion then notifies the
	 * end observer.
	 */
	end(ending: Ending): void {
		this.mode = "ended";
		this.delivery.end();

		if (ending === "completed") {
			this.onEnd?.(this.topic.name);
		}
	}
}

/**
 * The entries of the manager, keyed by topic name: at most one per topic.
 */
export class Entries {
	private readonly held = new Map<string, Entry>();

	/**
	 * The topic names currently subscribed (or awaiting reattach).
	 */
	get names(): readonly string[] {
		const names = [...this.held.keys()];
		return names;
	}

	/**
	 * Open the entry of `topic` over `delivery`.
	 *
	 * @throws SubscriptionError with code `AlreadySubscribed` when an entry
	 * already holds the topic.
	 */
	open(
		topic: Topic,
		delivery: Delivery,
		observers: Pick<SubscriptionObservers<unknown>, "onEnd" | "onGap">,
	): Entry {
		if (this.held.has(topic.name)) {
			const message = `already subscribed to topic: ${topic.name}`;
			throw new SubscriptionError("AlreadySubscribed", message);
		}

		const entry = new Entry(topic, delivery, observers, this);
		this.held.set(topic.name, entry);
		return entry;
	}

	/**
	 * The entry that holds the topic `name`.
	 */
	get(name: string): Entry | undefined {
		const entry = this.held.get(name);
		return entry;
	}

	/**
	 * Every entry.
	 */
	values(): IterableIterator<Entry> {
		const entries = this.held.values();
		return entries;
	}

	/**
	 * End `entry` for `ending` and take it out of the map in one step, while
	 * it holds its topic. Answers whether it did, and leaves a newer entry of
	 * the topic alone.
	 */
	end(entry: Entry, ending: Ending): boolean {
		const name = entry.topic.name;
		if (this.held.get(name) !== entry) {
			return false;
		}

		this.held.delete(name);
		entry.end(ending);
		return true;
	}

	/**
	 * End the entry of `topic` as completed. Answers whether an entry held
	 * the topic.
	 */
	complete(topic: Topic): boolean {
		const entry = this.held.get(topic.name);
		if (entry === undefined) {
			return false;
		}

		const ended = this.end(entry, "completed");
		return ended;
	}
}

/**
 * The serve handler that a manager installs on the serve port of each client.
 *
 * The handler reaches the manager until the manager detaches it, and then
 * answers every push as unrouted. A client that outlives its manager then
 * holds the attachment alone, and no part of the manager.
 */
class Attachment {
	#route: MuxStreamHandler | undefined;

	constructor(route: MuxStreamHandler) {
		this.#route = route;
	}

	/**
	 * The handler that a serve port holds.
	 */
	readonly handler: MuxStreamHandler = async (update) => {
		const route = this.#route;
		if (route === undefined) {
			const id = TEXT.decode(update.id);
			throw new UnroutedTopicError(id);
		}

		const routed = await route(update);
		return routed;
	};

	/**
	 * Stop reaching the manager, on every serve port that holds the handler.
	 */
	detach(): void {
		this.#route = undefined;
	}

	/**
	 * Refuse `operation` once the handler detached, because a disposed manager
	 * routes nothing.
	 *
	 * @throws SubscriptionError with code `Disposed` once the handler
	 * detached.
	 */
	requireAttached(operation: string): void {
		if (this.#route !== undefined) {
			return;
		}

		const message = `cannot ${operation}: the manager is disposed`;
		throw new SubscriptionError("Disposed", message);
	}
}

/**
 * Topic subscriptions over the {@link ClientPorts} of one client.
 *
 * Construction installs the serve handler immediately (exclusively), so
 * updates racing the `sub/` acknowledgment are never unrouted. After a
 * reconnect, pass the ports of the replacement client to {@link reattach}:
 * the commands the lost connection deferred replay, and the desired topics
 * re-subscribe. A disposal, through `await using` or
 * `[Symbol.asyncDispose]`, ends every subscription and detaches the serve
 * handler.
 */
export class SubscriptionManager {
	private ports: ClientPorts;

	private readonly entries = new Entries();

	/**
	 * The lane of each topic with a command in flight or deferred. A lane
	 * leaves the map once it goes idle.
	 */
	private readonly lanes = new Map<string, CommandLane>();

	/**
	 * The one deferral budget of every lane of the manager.
	 */
	private readonly deferrals = new DeferralBudget();

	private readonly fallback: MuxStreamHandler | undefined;

	/**
	 * The serve handler of the manager, on the serve port of every client it
	 * attached to.
	 */
	private readonly attachment: Attachment;

	constructor(ports: ClientPorts, options?: ManagerOptions) {
		this.ports = ports;
		this.fallback = options?.fallback;

		const route: MuxStreamHandler = (update) => this.dispatch(update);
		this.attachment = new Attachment(route);
		this.install();
	}

	/**
	 * The topics currently subscribed (or awaiting reattach).
	 */
	get topics(): readonly string[] {
		return this.entries.names;
	}

	/**
	 * Subscribe to `topic`, resolving once the server acknowledges.
	 *
	 * The dispatch entry registers before the command leaves, so an
	 * update racing the acknowledgment still routes. A refusal
	 * (`PermissionDenied`, `Unavailable`, ...) removes the entry and
	 * rethrows. A connection loss keeps the topic in the desired set
	 * with a `deferred` state: delivery starts after {@link reattach}.
	 *
	 * With an `onUpdate` handler, the subscription is a
	 * {@link HandlerSubscription}. Without one, it is an
	 * {@link IteratingSubscription}.
	 *
	 * @throws TopicError for an invalid topic name, and SubscriptionError
	 * with code `AlreadySubscribed` when the topic is already subscribed, or
	 * `Disposed` once the manager is disposed.
	 */
	subscribe<T>(
		topic: Topic | string,
		options: SubscribeOptions<T> & { readonly onUpdate: UpdateHandler<T> },
	): Promise<HandlerSubscription>;
	subscribe<T>(
		topic: Topic | string,
		options: SubscribeOptions<T> & { readonly onUpdate?: undefined },
	): Promise<IteratingSubscription<T>>;
	async subscribe<T>(
		topic: Topic | string,
		options: SubscribeOptions<T>,
	): Promise<HandlerSubscription | IteratingSubscription<T>> {
		this.attachment.requireAttached("subscribe");

		const parsed = Topic.parse(topic);
		const delivery = Delivery.of(parsed, options, this.ports.engine);
		const entry = this.entries.open(parsed, delivery, options);
		const release = (): Promise<void> => this.release(entry);
		const subscription = delivery.handle(entry, release);

		const subscribing = parsed.subscribe();
		await this.send(subscribing, entry);
		return subscription;
	}

	/**
	 * Publish `message` on `topic` through the wire's `pub/<topic>`
	 * command, resolving once the server acknowledges or a connection loss
	 * defers the command to {@link reattach}.
	 *
	 * A `codec` source encodes the message directly as the command's body.
	 * An `envelope` source publishes frame-in-frame: the message travels as
	 * a full inner frame with the envelope's declared layers applied, which
	 * the registry relays byte-for-byte.
	 *
	 * The server must enable client publish (a `PublishPolicy` on its
	 * `PubsubCommands`). Otherwise the command falls through to its
	 * application routes and typically rejects `Unimplemented`.
	 *
	 * @throws TopicError for an invalid topic name, and SubscriptionError
	 * with code `Disposed` once the manager is disposed.
	 */
	async publish<T>(
		topic: Topic | string,
		message: T,
		source: PayloadSource<T>,
	): Promise<void> {
		this.attachment.requireAttached("publish");

		const parsed = Topic.parse(topic);
		const shape = PayloadShape.of(source, this.ports.engine, "building");
		const body: CommandBody = (command) => shape.build(command, message);

		const publishing = parsed.publish(body, shape);
		await this.send(publishing);
	}

	/**
	 * Emit `unsub/<topic>` and stop dispatching the topic locally.
	 *
	 * Local removal happens first and is the fence: an update already
	 * in flight re-checks it after every await, so no update dispatches
	 * after this call regardless of the command's fate. The `unsub/`
	 * leaves after a `sub/` still pending for the topic settles. A
	 * connection loss defers it to {@link reattach}.
	 *
	 * @throws TopicError for an invalid topic name.
	 */
	async unsubscribe(topic: Topic | string): Promise<void> {
		const parsed = Topic.parse(topic);
		const entry = this.entries.get(parsed.name);
		if (entry === undefined) {
			return;
		}

		await this.release(entry);
	}

	/**
	 * Resume on the ports of a replacement connection after the previous
	 * one closed. Installs the serve handler, then gives each topic a new
	 * lane whose first turn replays the topic:
	 *
	 * 1. The replay waits for the commands still in flight on the old lane.
	 * 2. A subscription that was live re-sends its `sub/`, and its gate
	 *    re-baselines on the next update.
	 * 3. The commands the lost connection deferred follow, in the order they
	 *    were sent.
	 *
	 * Every command sent after this call follows the replay of its topic.
	 * A refused `sub/` replay ends its topic, and a connection loss defers
	 * the command for the next reattach. When the server refused any replay,
	 * an `AggregateError` of every refusal throws after all settle. The
	 * surviving topics are already consistent.
	 *
	 * @throws SubscriptionError with code `Disposed` once the manager is
	 * disposed, before it installs any handler.
	 */
	async reattach(ports: ClientPorts): Promise<void> {
		this.attachment.requireAttached("reattach");

		this.ports = ports;
		this.install();

		const topics = new Map<string, Topic>();
		for (const lane of this.lanes.values()) {
			topics.set(lane.topic.name, lane.topic);
		}
		for (const entry of this.entries.values()) {
			topics.set(entry.topic.name, entry.topic);
		}

		const replays: Promise<unknown[]>[] = [];
		for (const topic of topics.values()) {
			const lost = this.lanes.get(topic.name);
			const subscriber = this.entries.get(topic.name);
			const lane = ports.lane(topic, this.deferrals);
			this.lanes.set(topic.name, lane);

			const replayed = lane.adopt(lost, subscriber);
			void this.retire(lane, replayed);
			replays.push(replayed);
		}

		const settled = await Promise.all(replays);
		const refusals = settled.flat();
		if (refusals.length > 0) {
			const message = "some commands were refused on reattach";
			throw new AggregateError(refusals, message);
		}
	}

	/**
	 * Dispose the manager. The serve handler detaches first, so no later push
	 * reaches the manager, and every subscription then ends and sends its
	 * `unsub/` through the lane of its topic. Resolves once every `unsub/`
	 * settles and every lane drops what its lost connection deferred, after
	 * the commands still in flight settle, and a later disposal ends nothing
	 * more. A later `subscribe`, `publish`, or `reattach` refuses with
	 * `Disposed`.
	 *
	 * When the server refused any `unsub/`, an `AggregateError` of every
	 * refusal throws after all settle.
	 */
	async [Symbol.asyncDispose](): Promise<void> {
		this.attachment.detach();

		const ending = [...this.entries.values()];
		const releases: Promise<void>[] = [];
		for (const entry of ending) {
			const released = this.release(entry);
			releases.push(released);
		}

		const settled = await Promise.allSettled(releases);
		const lanes = [...this.lanes.values()];
		const dropping = lanes.map((lane) => lane[Symbol.asyncDispose]());
		await Promise.all(dropping);

		const refusals: unknown[] = [];
		for (const outcome of settled) {
			if (outcome.status === "rejected") {
				refusals.push(outcome.reason);
			}
		}

		if (refusals.length > 0) {
			const message = "some unsub/ commands were refused on dispose";
			throw new AggregateError(refusals, message);
		}
	}

	/**
	 * Unsubscribe `entry` as {@link unsubscribe} does, while `entry` still
	 * holds its topic. The handle of an ended subscription then leaves a newer
	 * subscription to the same topic alone.
	 */
	private async release(entry: Entry): Promise<void> {
		const released = this.entries.end(entry, "unsubscribed");
		if (!released) {
			return;
		}

		const leaving = entry.topic.unsubscribe();
		await this.send(leaving);
	}

	/**
	 * Re-send `sub/` for `entry` to answer a gap, so a replay-capable server
	 * fills it.
	 */
	private async resync(entry: Entry): Promise<void> {
		const resubscribing = entry.topic.subscribe();
		await this.send(resubscribing, entry);
	}

	/**
	 * Send `command` through the lane of its topic, for `subscriber`.
	 */
	private send(command: Command, subscriber?: Subscriber): Promise<void> {
		const lane = this.laneOf(command.topic);
		const sent = lane.send(command, subscriber);
		void this.retire(lane, sent);
		return sent;
	}

	/**
	 * The lane of `topic` over the current ports, made on first use.
	 */
	private laneOf(topic: Topic): CommandLane {
		const held = this.lanes.get(topic.name);
		if (held !== undefined) {
			return held;
		}

		const lane = this.ports.lane(topic, this.deferrals);
		this.lanes.set(topic.name, lane);
		return lane;
	}

	/**
	 * Forget `lane` once `settling` settles and the lane goes idle, unless a
	 * later lane took its place.
	 */
	private async retire(
		lane: CommandLane,
		settling: Promise<unknown>,
	): Promise<void> {
		await whenSettled(settling);

		const name = lane.topic.name;
		const current = this.lanes.get(name) === lane;
		if (current && lane.idle) {
			this.lanes.delete(name);
		}
	}

	/**
	 * Register the handler of the attachment on the current serve port,
	 * claiming dispatch exclusively so a later `client.serve` cannot silently
	 * unroute updates.
	 *
	 * The client holds the attachment, which reaches the manager until a
	 * disposal detaches it.
	 */
	private install(): void {
		const handler = this.attachment.handler;
		this.ports.serving.serve(handler, { claim: "exclusive" });
	}

	/**
	 * Route one server-initiated stream.
	 */
	private async dispatch(update: Frame): Promise<Frame | undefined | null> {
		const id = TEXT.decode(update.id);
		const completed = Command.parse(id)?.completed;
		if (completed !== undefined) {
			const ended = this.entries.complete(completed);
			if (ended) {
				return undefined;
			}

			return this.unmatched(update, id);
		}

		const entry = this.entries.get(id);
		if (entry === undefined) {
			return this.unmatched(update, id);
		}

		const resync = (): Promise<void> => this.resync(entry);
		await entry.receive(update, resync);
		return undefined;
	}

	/**
	 * Hand an unmatched stream to the fallback, or answer
	 * `Unimplemented`.
	 */
	private unmatched(
		update: Frame,
		id: string,
	): Promise<Frame | undefined | null> | Frame | undefined | null {
		if (this.fallback !== undefined) {
			return this.fallback(update);
		}

		throw new UnroutedTopicError(id);
	}
}
