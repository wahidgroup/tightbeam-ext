/**
 * The subscription manager of one multiplexed tightbeam client. The page
 * `docs/pubsub-client.md` states its ports, its commands, and its dispatch.
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
import { HeldCodec, UnroutedTopicError } from "@wahidgroup/tightbeam-ws-client";

import type { Gap, Stamp } from "./gate.js";
import type { CommandPayload } from "./topic.js";
import { PullChannel } from "./channel.js";
import { TopicGate } from "./gate.js";
import { Push, Topic } from "./topic.js";
import type { Command } from "./topic.js";

/**
 * The decoder of the id that labels an unrouted push. It keeps a leading
 * U+FEFF, so the label names the topic the server pushed.
 */
const TEXT = new TextDecoder("utf-8", { ignoreBOM: true });

/**
 * One decoded update: the typed message, the frame that carried it, and
 * the topic that routed it.
 */
export interface Update<T> {
	readonly message: T;
	readonly frame: Frame;
	readonly topic: Topic;
}

/**
 * Receives one decoded update. The manager acknowledges the stream once the
 * result settles, so a slow handler slows the delivery lane of the server.
 */
export type UpdateHandler<T> = (message: T, frame: Frame, topic: Topic) => void | Promise<void>;

/**
 * Observes a detected gap: the updates from `gap.expected` up to
 * `gap.received` were lost for this subscriber.
 *
 * - An update that revealed the gap still delivers. A throw of the observer
 *   surfaces only after that delivery settles.
 * - An `end/<topic>` that reveals the gap passes one past the last order of
 *   the topic as `gap.received`.
 */
export type GapHandler = (topic: Topic, gap: Gap) => void | Promise<void>;

/**
 * Observes topic completion: the server pushed `end/<topic>` (drain).
 * The subscription is already removed when this fires.
 */
export type EndHandler = (topic: Topic) => void;

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
 * How the updates of a subscription carry its payload, in exactly one of
 * two shapes:
 *
 * - `codec`: the frame body is the message under a {@link MessageCodec}.
 * - `envelope`: the frame body carries a full inner frame, unwrapped
 *   (verified, opened, inflated, decoded) under the declared layers of an
 *   {@link Envelope} that holds every receive half.
 */
export type SubscribePayload<T> =
	| {
			readonly codec: MessageCodec<T>;
			readonly envelope?: undefined;
	  }
	| {
			readonly envelope: Envelope<T, boolean, true>;
			readonly codec?: undefined;
	  };

/**
 * How a publish carries its payload: a {@link MessageCodec}, or an
 * {@link Envelope} that holds every send half and builds a full inner frame
 * under its declared layers.
 */
export type PublishPayload<T> =
	| {
			readonly codec: MessageCodec<T>;
			readonly envelope?: undefined;
	  }
	| {
			readonly envelope: Envelope<T, true, boolean>;
			readonly codec?: undefined;
	  };

/**
 * Everything one subscription needs: how updates decode, plus the
 * observers.
 */
export type SubscribeOptions<T> = SubscriptionObservers<T> & SubscribePayload<T>;

/**
 * How a subscription decodes the message an update frame carries.
 */
export interface DecodingShape<T> {
	/**
	 * Decode the message that `update` carries.
	 */
	decode(update: Frame): Promise<T>;
}

/**
 * The codec kind of a subscription: the body is the message under a codec.
 * The shape holds the codec of the caller and reads no handle of it, so the
 * caller may free its content type.
 */
class CodecDecoding<T> implements DecodingShape<T> {
	readonly #codec: MessageCodec<T>;

	constructor(codec: MessageCodec<T>) {
		this.#codec = codec;
	}

	decode(update: Frame): Promise<T> {
		const message = update.open(this.#codec);
		return message;
	}
}

/**
 * The envelope kind of a subscription: the body is a full inner frame,
 * carried by the `framed` codec of the engine, which unwraps under the
 * declared layers of the envelope.
 */
class EnvelopeDecoding<T> implements DecodingShape<T> {
	readonly #envelope: Envelope<T, boolean, true>;

	readonly #framed: MessageCodec<Frame>;

	constructor(envelope: Envelope<T, boolean, true>, framed: MessageCodec<Frame>) {
		this.#envelope = envelope;
		this.#framed = framed;
	}

	async decode(update: Frame): Promise<T> {
		const inner = await update.open(this.#framed);
		const message = await this.#envelope.unwrap(inner);
		return message;
	}
}

/**
 * The codec kind of a publish. The command builds its frame at its turn,
 * possibly after a reconnect, so the payload holds the codec under a copy of
 * its content type and frees the copy as the command settles.
 */
class CodecBuilding<T> implements CommandPayload {
	readonly #held: HeldCodec<T>;

	readonly #message: T;

	constructor(codec: MessageCodec<T>, message: T) {
		this.#held = HeldCodec.of(codec);
		this.#message = message;
	}

	begin(engine: Engine): FrameBuilder {
		const begun = engine.messageBuilder(this.#held, this.#message);
		return begun;
	}

	[Symbol.dispose](): void {
		this.#held[Symbol.dispose]();
	}
}

/**
 * The envelope kind of a publish: the body is a full inner frame under the
 * declared layers of the envelope, which the registry relays byte for byte.
 * The inner frame takes the topic as its id, and the `framed` codec of the
 * engine carries it.
 */
class EnvelopeBuilding<T> implements CommandPayload {
	readonly #envelope: Envelope<T, true, boolean>;

	readonly #message: T;

	constructor(envelope: Envelope<T, true, boolean>, message: T) {
		this.#envelope = envelope;
		this.#message = message;
	}

	async begin(engine: Engine, topic: Topic): Promise<FrameBuilder> {
		const layered = this.#envelope.frame(this.#message);
		const inner = await layered.withId(topic.name).build();
		const begun = engine.messageBuilder(engine.framed, inner);
		return begun;
	}

	/**
	 * Free nothing, because the envelope keeps the copies it took for as long
	 * as it lives.
	 */
	[Symbol.dispose](): void {
		return;
	}
}

/**
 * The payload shapes of a topic. Each factory picks the kind its payload
 * names, so no other step asks which kind it holds.
 */
export const PayloadShape = {
	/**
	 * The shape that decodes the updates of a subscription under `payload`,
	 * through `engine`.
	 */
	decoding<T>(payload: SubscribePayload<T>, engine: Engine): DecodingShape<T> {
		if (payload.envelope !== undefined) {
			const shape = new EnvelopeDecoding(payload.envelope, engine.framed);
			return shape;
		}

		const shape = new CodecDecoding(payload.codec);
		return shape;
	},

	/**
	 * The body of the `pub/` command that publishes `message` under
	 * `payload`. A codec body holds a copy of every handle it reads at the
	 * turn of its command, freed as the command settles.
	 */
	building<T>(payload: PublishPayload<T>, message: T): CommandPayload {
		if (payload.envelope !== undefined) {
			const body = new EnvelopeBuilding(payload.envelope, message);
			return body;
		}

		const body = new CodecBuilding(payload.codec, message);
		return body;
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
 * The rule that a refused subscription call breaks. The page
 * `docs/pubsub-client.md` (Subscriptions) states each one.
 */
export type SubscriptionErrorCode = "AlreadySubscribed" | "AlreadyIterating" | "Disposed" | "DeferralFull";

/**
 * The most commands that the lanes of one manager keep, across every topic,
 * for a lost connection. A command past the budget refuses with
 * `DeferralFull`, so an outage holds bounded memory however many topics it
 * spans (CWE-770).
 */
export const MAX_DEFERRED = 256;

/**
 * The deferral budget of one manager: the slots of {@link MAX_DEFERRED} that
 * its lanes hold. A lane draws a slot as it defers a command, and the
 * deferred command holds it until it leaves its queue: on a replay, or on a
 * drop.
 */
export class DeferralBudget {
	#held = 0;

	/**
	 * Take one slot, or answer `undefined` when every slot is held. The
	 * disposal of the slot returns it once, however often it runs.
	 */
	draw(): Disposable | undefined {
		if (this.#held >= MAX_DEFERRED) {
			return undefined;
		}

		this.#held += 1;
		let held = true;
		const slot: Disposable = {
			[Symbol.dispose]: (): void => {
				if (held) {
					held = false;
					this.#held -= 1;
				}
			},
		};
		return slot;
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
	 * The topic the subscription dispatches.
	 */
	readonly topic: Topic;

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

	/**
	 * Resolve once the subscription has ended and every update it began to
	 * deliver has settled: delivered before the end, or dropped by it.
	 */
	settled(): Promise<void>;
}

/**
 * The handle of a subscription without an `onUpdate` handler: the members
 * of a {@link HandlerSubscription}, plus the one iterator that delivers
 * each update.
 *
 * ```ts
 * const prices = await manager.subscribe("prices", { codec: engine.opaque });
 * for await (const { message, frame } of prices) {
 * 	render(message, frame.order);
 * }
 * ```
 *
 * - Iteration ends when the topic completes or unsubscribes.
 * - A `break` out of the loop unsubscribes the topic.
 */
export interface IteratingSubscription<T> extends HandlerSubscription, AsyncIterable<Update<T>> {
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
	 * Lapse with the lost connection, and answer the `sub/` the subscription
	 * replays, or `undefined` when it was not live. A lapsed subscription
	 * replays its `sub/` before the deferred commands, because it was
	 * acknowledged before any of them was sent.
	 */
	lapse(): Command | undefined;
}

/**
 * One command a lane replays, with the subscriber it speaks for.
 */
interface Replay {
	readonly command: Command;
	readonly subscriber: Subscriber | undefined;
}

/**
 * A command that a lost connection deferred, with the subscriber it speaks
 * for and the slot of the deferral budget it holds.
 */
class Deferred implements Disposable {
	readonly #replay: Replay;

	readonly #slot: Disposable;

	constructor(replay: Replay, slot: Disposable) {
		this.#replay = replay;
		this.#slot = slot;
	}

	/**
	 * Leave the queue for a replay: return the slot, and hand over the
	 * command, which the replay settles.
	 */
	replay(): Replay {
		this.#slot[Symbol.dispose]();
		return this.#replay;
	}

	/**
	 * Drop the command: return the slot, and free what the command holds.
	 */
	[Symbol.dispose](): void {
		this.#slot[Symbol.dispose]();
		this.#replay.command[Symbol.dispose]();
	}
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

	constructor(topic: Topic, port: CommandPort, engine: Engine, budget: DeferralBudget) {
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
	 * 1. The replay waits for `lost` to settle.
	 * 2. A lapsed `subscriber` replays its `sub/` first.
	 * 3. The deferred commands follow in the order they were sent.
	 *
	 * Resolves with the refusal of each replayed command the server refused.
	 */
	adopt(lost: CommandLane | undefined, subscriber: Subscriber | undefined): Promise<unknown[]> {
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
	async #replay(lost: CommandLane | undefined, subscriber: Subscriber | undefined): Promise<unknown[]> {
		const replays: Replay[] = [];
		if (lost !== undefined) {
			await lost.#tail;
			for (const deferred of lost.#deferred.splice(0)) {
				replays.push(deferred.replay());
			}
		}

		const resubscribing = subscriber?.lapse();
		if (resubscribing !== undefined) {
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
			const closed = this.#engine.isTransportError(failure) && failure.code === "ConnectionClosed";
			if (!closed) {
				subscriber?.refused();
				throw failure;
			}

			const slot = this.#budget.draw();
			if (slot === undefined) {
				subscriber?.refused();
				const message = `the manager already holds ${MAX_DEFERRED} deferred commands`;
				throw new SubscriptionError("DeferralFull", message);
			}

			const deferred = new Deferred({ command, subscriber }, slot);
			this.#deferred.push(deferred);
			subscriber?.deferred();
			return true;
		}

		subscriber?.acknowledged();
		return false;
	}

	/**
	 * Wait for the turns in flight, then drop the commands the lost
	 * connection deferred, which no replay will send, and free what each one
	 * holds.
	 *
	 * - A command that defers while the disposal waits drops with the rest.
	 * - The wait ends as each command settles: the server answers it, or the client closes, which
	 *   settles every pending emit with `ConnectionClosed`.
	 */
	async [Symbol.asyncDispose](): Promise<void> {
		await this.#tail;

		for (const dropped of this.#deferred.splice(0)) {
			dropped[Symbol.dispose]();
		}
	}
}

/**
 * The key of the member of {@link ClientPorts} that opens a lane. The module
 * keeps it, so only the manager opens one.
 */
const OPEN_LANE: unique symbol = Symbol("ClientPorts.openLane");

/**
 * A client split once into the uses the manager makes of it.
 *
 * - The command port sits in a private field that only the lanes of the manager read, so every
 *   command the manager sends passes a lane.
 * - The manager reaches the {@link ServePort} alone, which holds no `emit`, and through it the
 *   engine that dialed the client.
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
	[OPEN_LANE](topic: Topic, budget: DeferralBudget): CommandLane {
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
		private readonly shape: DecodingShape<T>,
		private readonly onUpdate: UpdateHandler<T>,
	) {}

	async deliver(update: Frame, live: () => boolean): Promise<void> {
		const message = await this.shape.decode(update);
		if (!live()) {
			return;
		}

		await this.onUpdate(message, update, this.topic);
	}

	end(): void {
		// Each update reaches the handler as it arrives, so no queue waits.
	}

	/**
	 * The handle of `entry`, which `release` unsubscribes.
	 */
	handle(entry: Entry, release: () => Promise<void>): HandlerSubscription {
		const subscription: HandlerSubscription = {
			topic: this.topic,
			get state(): SubscriptionState {
				return entry.state;
			},
			unsubscribe: release,
			settled: () => entry.settled(),
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
		private readonly shape: DecodingShape<T>,
	) {}

	async deliver(update: Frame, live: () => boolean): Promise<void> {
		const message = await this.shape.decode(update);
		if (!live()) {
			return;
		}

		const pulled: Update<T> = {
			message,
			frame: update,
			topic: this.topic,
		};
		await this.channel.put(pulled);
	}

	end(): void {
		this.channel.finish();
	}

	/**
	 * The handle of `entry`, which `release` unsubscribes.
	 */
	handle(entry: Entry, release: () => Promise<void>): IteratingSubscription<T> {
		const iterate = (): AsyncIterator<Update<T>> => this.iterator(release);
		const subscription: IteratingSubscription<T> = {
			topic: this.topic,
			get state(): SubscriptionState {
				return entry.state;
			},
			unsubscribe: release,
			settled: () => entry.settled(),
			[Symbol.asyncIterator]: iterate,
		};
		return subscription;
	}

	/**
	 * The one iterator over the channel. Its `return` runs `release`.
	 */
	private iterator(release: () => Promise<void>): AsyncIterator<Update<T>> {
		if (this.iterated) {
			const message = "a subscription has one iterator: keep the first one, or subscribe again";
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
	of<T>(topic: Topic, options: SubscribeOptions<T>, engine: Engine): HandlerDelivery<T> | ChannelDelivery<T> {
		const shape = PayloadShape.decoding(options, engine);
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
 * The observers an entry takes: the gap observer, and the end observer.
 */
export interface EntryObservers {
	readonly onGap?: GapHandler | undefined;
	readonly onEnd?: EndHandler | undefined;
}

/**
 * Where an entry stands. Each mode maps to one {@link SubscriptionState},
 * and two modes hold what the state hides:
 *
 * - `unsent`: pending, and its first `sub/` has not left.
 * - `abandoned`: ended before its first `sub/` left. That `sub/` still
 *   leaves, so the server answers the subscribe call.
 */
type Mode = "unsent" | "pending" | "live" | "deferred" | "abandoned" | "ended";

/**
 * The public state of each mode.
 */
const STATE_OF_MODE: Readonly<Record<Mode, SubscriptionState>> = {
	unsent: "pending",
	pending: "pending",
	live: "live",
	deferred: "deferred",
	abandoned: "ended",
	ended: "ended",
};

/**
 * The dispatch record of one subscription while its topic stays desired.
 *
 * - {@link Entries.end} ends an entry in the same step that removes it from the map, so an entry
 *   is open exactly while it holds its topic.
 * - That is the unsubscribe fence: the delivery path re-checks it after every await, so in-flight
 *   work respects unsubscribe and completion.
 * - Against {@link TopicGate}, classify before delivery, and settle the stamp of the update once
 *   the delivery settles.
 * - The mode moves only through the {@link Subscriber} answers and {@link end}, and an ended
 *   entry stays ended.
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

	private mode: Mode = "unsent";

	/**
	 * The updates whose delivery began and has not settled.
	 */
	private delivering = 0;

	/**
	 * The callers of {@link settled} that wait for the entry to end and its
	 * deliveries to settle.
	 */
	private readonly waiters: (() => void)[] = [];

	constructor(topic: Topic, delivery: Delivery, observers: EntryObservers, entries: Entries) {
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
		const state = STATE_OF_MODE[this.mode];
		return state;
	}

	/**
	 * Whether the entry still holds its topic.
	 */
	private get open(): boolean {
		const open = this.state !== "ended";
		return open;
	}

	/**
	 * Whether a push of the topic reaches this entry: its `sub/` left on the
	 * current connection. A push that arrives before then belongs to an
	 * earlier subscription of the topic.
	 */
	get reachable(): boolean {
		const reachable = this.mode === "pending" || this.mode === "live";
		return reachable;
	}

	/**
	 * Receive one update: classify it against the gate, report a gap it
	 * reveals, deliver it, then settle its stamp.
	 *
	 * - The gap observer runs before the delivery.
	 * - The update delivers even when the observer fails, and that failure
	 *   throws once the delivery settles. A failed delivery throws in its
	 *   place.
	 */
	async receive(update: Frame): Promise<void> {
		const order = update.order;
		const verdict = this.gate.classify(order);
		if (verdict.kind === "stale") {
			return;
		}

		this.delivering += 1;
		try {
			let answered: HeldFailure | undefined;
			if (verdict.kind === "gap") {
				answered = await this.answerGap(verdict.gap);
			}

			const delivered = await this.deliverWhileOpen(update, verdict.stamp);
			const failure = delivered ?? answered;
			if (failure !== undefined) {
				throw failure.cause;
			}
		} finally {
			this.delivering -= 1;
			this.wake();
		}
	}

	/**
	 * Resolve once the entry has ended and every update it began to deliver
	 * has settled.
	 */
	settled(): Promise<void> {
		if (this.quiet) {
			return Promise.resolve();
		}

		const waiting = new Promise<void>((resolve) => {
			this.waiters.push(resolve);
		});
		return waiting;
	}

	/**
	 * Whether the entry has ended with no delivery in flight.
	 */
	private get quiet(): boolean {
		const quiet = !this.open && this.delivering === 0;
		return quiet;
	}

	/**
	 * Release the callers of {@link settled} once the entry is quiet.
	 */
	private wake(): void {
		if (!this.quiet) {
			return;
		}

		for (const waiter of this.waiters.splice(0)) {
			waiter();
		}
	}

	/**
	 * Report `gap` to the gap observer. Its failure is held, so the revealing
	 * update still delivers.
	 */
	private async answerGap(gap: Gap): Promise<HeldFailure | undefined> {
		try {
			await this.onGap?.(this.topic, gap);
		} catch (cause) {
			const failure = { cause };
			return failure;
		}

		return undefined;
	}

	/**
	 * Deliver `update` while the entry stays open, then settle its `stamp`:
	 * delivered, or failed, so the next update reveals the loss as a gap
	 * even before any baseline.
	 */
	private async deliverWhileOpen(update: Frame, stamp: Stamp): Promise<HeldFailure | undefined> {
		if (!this.open) {
			return undefined;
		}

		const live = (): boolean => this.open;
		try {
			await this.delivery.deliver(update, live);
		} catch (cause) {
			stamp.failed();
			const failure = { cause };
			return failure;
		}

		stamp.delivered();
		return undefined;
	}

	/**
	 * Complete the subscription at `order`, the last order of its topic, as
	 * the `end/<topic>` of a drain carries it, then end it.
	 *
	 * - One past `order` classifies against the gate, so each update after the baseline that the
	 *   subscription lost reports as a gap first.
	 * - An entry that still held its topic notifies the end observer once it ended.
	 * - A failure of the gap observer throws once the entry ended.
	 */
	async complete(order: bigint): Promise<void> {
		const verdict = this.gate.classify(order + 1n);
		let answered: HeldFailure | undefined;
		if (verdict.kind === "gap") {
			answered = await this.answerGap(verdict.gap);
		}

		const ended = this.entries.end(this);
		if (ended) {
			this.onEnd?.(this.topic);
		}

		if (answered !== undefined) {
			throw answered.cause;
		}
	}

	/**
	 * The first `sub/` of the entry always leaves, so the server answers the
	 * subscribe call. A replay leaves while the entry holds its topic.
	 */
	wants(): boolean {
		const wanted = this.mode !== "ended";
		return wanted;
	}

	/**
	 * A `sub/` leaves: an unsent or deferred subscription is pending, and an
	 * abandoned one has sent the `sub/` it owed.
	 */
	leaving(): void {
		if (this.mode === "unsent" || this.mode === "deferred") {
			this.mode = "pending";
			return;
		}
		if (this.mode === "abandoned") {
			this.mode = "ended";
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
	 * The server refused `sub/`: a pending subscription ends.
	 */
	refused(): void {
		if (this.mode === "pending") {
			this.entries.end(this);
		}
	}

	/**
	 * The subscription lapses with its lost connection: its gate resets in
	 * every mode, so the next update of the replacement connection
	 * re-baselines. A live one waits for the replay. Answers the `sub/` it
	 * replays, or `undefined` when it was not live.
	 */
	lapse(): Command | undefined {
		this.gate.reset();
		if (this.mode !== "live") {
			return undefined;
		}

		this.mode = "deferred";
		const resubscribing = this.topic.subscribe();
		return resubscribing;
	}

	/**
	 * End the subscription and its delivery.
	 */
	end(): void {
		if (this.mode === "unsent") {
			this.mode = "abandoned";
		} else {
			this.mode = "ended";
		}

		this.delivery.end();
		this.wake();
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
	open(topic: Topic, delivery: Delivery, observers: EntryObservers): Entry {
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
	 * The entries in the order they opened.
	 */
	values(): IterableIterator<Entry> {
		const entries = this.held.values();
		return entries;
	}

	/**
	 * End `entry` and take it out of the map in one step, while it holds its topic.
	 * Answers whether it did, and leaves a newer entry of the topic alone.
	 */
	end(entry: Entry): boolean {
		const name = entry.topic.name;
		if (this.held.get(name) !== entry) {
			return false;
		}

		this.held.delete(name);
		entry.end();
		return true;
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
 * The constructor claims the serve port of the client exclusively, so an
 * update that races the acknowledgment of its `sub/` still routes.
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
		this.install(ports);
	}

	/**
	 * The topics currently subscribed (or awaiting reattach).
	 */
	get topics(): readonly string[] {
		return this.entries.names;
	}

	/**
	 * Subscribe to `topic`, and resolve once the server acknowledges.
	 *
	 * - A refusal of the server removes the entry and throws.
	 * - A lost connection keeps the subscription `deferred` until
	 *   {@link reattach}.
	 * - With an `onUpdate` handler, the subscription is a
	 *   {@link HandlerSubscription}, and without one an
	 *   {@link IteratingSubscription}.
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
		const observers = { onGap: options.onGap, onEnd: options.onEnd };
		const entry = this.entries.open(parsed, delivery, observers);
		const release = (): Promise<void> => this.release(entry);
		const subscription = delivery.handle(entry, release);

		const subscribing = parsed.subscribe();
		await this.send(subscribing, entry);
		return subscription;
	}

	/**
	 * Publish `message` on `topic` with a `pub/<topic>` command, and resolve
	 * once the server acknowledges or a lost connection defers the command to
	 * {@link reattach}.
	 *
	 * The page `docs/pubsub-client.md` (Publish) states each payload shape.
	 *
	 * @throws TopicError for an invalid topic name.
	 * @throws SubscriptionError with code `Disposed` once the manager is disposed.
	 */
	async publish<T>(topic: Topic | string, message: T, payload: PublishPayload<T>): Promise<void> {
		this.attachment.requireAttached("publish");

		const parsed = Topic.parse(topic);
		const body = PayloadShape.building(payload, message);
		const publishing = parsed.publish(body);
		await this.send(publishing);
	}

	/**
	 * Stop dispatching `topic` locally, then emit `unsub/<topic>` once a
	 * `sub/` still pending for the topic settles.
	 *
	 * The local removal is the fence: an update in flight re-checks it after
	 * every await, so no update dispatches after this call.
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
	 * one closed. Installs the serve handler on the new client first, then
	 * gives each topic a new lane whose first turn replays the topic:
	 *
	 * 1. The replay waits for the commands still in flight on the old lane.
	 * 2. The gate of the subscription resets, and a subscription that was live
	 *    re-sends its `sub/`.
	 * 3. The commands the lost connection deferred follow, in the order they
	 *    were sent.
	 *
	 * - Every command sent after this call follows the replay of its topic.
	 * - A refused `sub/` replay ends its topic.
	 * - When the server refused any replay, an `AggregateError` of every refusal throws once all settle.
	 *
	 * @throws SubscriptionError with code `Disposed` once the manager is disposed, before it installs any handler.
	 * @throws The serve refusal of a new client, which leaves the manager on the ports it had.
	 */
	async reattach(ports: ClientPorts): Promise<void> {
		this.attachment.requireAttached("reattach");

		this.install(ports);
		this.ports = ports;

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
			const lane = ports[OPEN_LANE](topic, this.deferrals);
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
	 * Detach the serve handler, then end every subscription and send its
	 * `unsub/`. The page `docs/pubsub-client.md` (Manager) states when the
	 * disposal resolves.
	 *
	 * @throws AggregateError of every `unsub/` that the server refused, once all settle.
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
		const released = this.entries.end(entry);
		if (!released) {
			return;
		}

		const leaving = entry.topic.unsubscribe();
		await this.send(leaving);
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

		const lane = this.ports[OPEN_LANE](topic, this.deferrals);
		this.lanes.set(topic.name, lane);
		return lane;
	}

	/**
	 * Forget `lane` once `settling` settles and the lane goes idle, unless a
	 * later lane took its place.
	 */
	private async retire(lane: CommandLane, settling: Promise<unknown>): Promise<void> {
		await whenSettled(settling);

		const name = lane.topic.name;
		const current = this.lanes.get(name) === lane;
		if (current && lane.idle) {
			this.lanes.delete(name);
		}
	}

	/**
	 * Register the handler of the attachment on the serve port of `ports`,
	 * claiming dispatch exclusively, so every update stays routed to the manager.
	 *
	 * The client holds the attachment, which reaches the manager until a disposal detaches it.
	 */
	private install(ports: ClientPorts): void {
		const handler = this.attachment.handler;
		ports.serving.serve(handler, { claim: "exclusive" });
	}

	/**
	 * Route one server-initiated stream by its id, parsed once: a push of a
	 * topic to the entry that the push reaches, and every other push to the
	 * fallback.
	 */
	private async dispatch(update: Frame): Promise<Frame | undefined | null> {
		const push = Push.parse(update.id);
		if (push === undefined) {
			return this.unmatched(update);
		}

		const entry = this.entries.get(push.topic.name);
		if (entry === undefined || !entry.reachable) {
			return this.unmatched(update);
		}

		await Push.route(push, entry, update);
		return undefined;
	}

	/**
	 * Hand an unmatched stream to the fallback, or answer
	 * `Unimplemented`.
	 */
	private unmatched(update: Frame): Promise<Frame | undefined | null> | Frame | undefined | null {
		if (this.fallback !== undefined) {
			return this.fallback(update);
		}

		const id = TEXT.decode(update.id);
		throw new UnroutedTopicError(id);
	}
}
