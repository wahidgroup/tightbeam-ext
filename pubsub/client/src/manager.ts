/**
 * Client-side subscription lifecycle over a multiplexed tightbeam
 * connection.
 *
 * The manager owns the client's serve handler (an exclusive claim, so a
 * later `client.serve` throws instead of silently unrouting updates):
 * updates dispatch by exact topic match, `end/<topic>` completes a
 * subscription, and anything else falls through to the application's
 * own {@link ManagerOptions.fallback} (or answers `Unimplemented`).
 *
 * Subscribing emits a `sub/<topic>` command stream; the server's `Ok`
 * answer resolves it. Publishing emits `pub/<topic>` with the encoded
 * message, answered by servers that enable client publish.
 */

import type {
	Frame,
	MessageCodec,
	MuxStreamHandler,
	TightbeamWsClient,
} from "@wahidgroup/tightbeam-ws-client";
import {
	Envelope,
	Framed,
	UnroutedTopicError,
	frame,
	isTransportError,
} from "@wahidgroup/tightbeam-ws-client";

import { PullChannel } from "./channel.js";
import { TopicGate } from "./gate.js";
import {
	END_PREFIX,
	PUB_PREFIX,
	SUB_PREFIX,
	UNSUB_PREFIX,
	assertTopic,
} from "./topic.js";

const TEXT = new TextDecoder();

/**
 * Commands carry no payload; the id is the whole message.
 */
const EMPTY_BODY = new Uint8Array(0);

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
 * revealed the gap is still delivered. When omitted, the manager
 * re-emits the `sub/` command so a replay-capable server can resync.
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
 * {@link onUpdate} omitted, updates arrive by iterating the returned
 * {@link Subscription} instead.
 */
export interface SubscriptionObservers<T> {
	readonly onUpdate?: UpdateHandler<T>;
	readonly onGap?: GapHandler;
	readonly onEnd?: EndHandler;
}

/**
 * Everything one subscription needs: how updates decode, plus the
 * observers. Exactly one decoding shape:
 *
 * - `codec`: the update frame's body decodes directly under a
 *   {@link MessageCodec}.
 * - `envelope`: updates are frame-in-frame - the body carries a full
 *   inner frame, unwrapped (verified, opened, inflated, decoded) under
 *   the {@link Envelope}'s declared layers.
 */
export type SubscribeOptions<T> =
	| (SubscriptionObservers<T> & {
			readonly codec: MessageCodec<T>;
			readonly envelope?: undefined;
	  })
	| (SubscriptionObservers<T> & {
			readonly envelope: Envelope<T>;
			readonly codec?: undefined;
	  });

/**
 * Where one subscription stands.
 *
 * - `live`: the server acknowledged the `sub/` command.
 * - `pending`: awaiting acknowledgment, or parked across a connection
 *   loss until {@link SubscriptionManager.reattach} replays it.
 * - `ended`: unsubscribed or completed by the server.
 */
export type SubscriptionState = "live" | "pending" | "ended";

/**
 * One live subscription's handle. Without an `onUpdate` handler, the
 * subscription is async-iterable:
 *
 * ```ts
 * const prices = await manager.subscribe("prices", { codec: Opaque });
 * for await (const { message, frame } of prices) {
 *     render(message, frame.order);
 * }
 * ```
 *
 * Iteration ends when the topic completes or unsubscribes.
 */
export interface Subscription<T> extends AsyncIterable<Update<T>> {
	readonly topic: string;

	/**
	 * Where the subscription stands right now.
	 */
	readonly state: SubscriptionState;

	/**
	 * Emit `unsub/<topic>` and stop dispatching the topic locally.
	 */
	unsubscribe(): Promise<void>;
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
 * One topic's dispatch state: the ordering gate, the type-erased
 * delivery closure (the codec/handler pairing stays typed inside it),
 * the iteration terminator (iterator-mode subscriptions only), and the
 * lifecycle state.
 */
interface Entry {
	readonly gate: TopicGate;
	readonly deliver: (update: Frame) => Promise<void>;
	readonly finishIteration: (() => void) | undefined;
	readonly onGap: GapHandler | undefined;
	readonly onEnd: EndHandler | undefined;
	state: SubscriptionState;
}

/**
 * Whether a command rejection means "the connection is gone", which the
 * manager treats as "await reattach" rather than a topic-level failure.
 */
function isConnectionLoss(error: unknown): boolean {
	if (!isTransportError(error)) {
		return false;
	}
	return error.code === "ConnectionClosed";
}

/**
 * Topic subscriptions over one {@link TightbeamWsClient}.
 *
 * Construction installs the serve handler immediately (exclusively), so
 * updates racing the `sub/` acknowledgment are never unrouted. After a
 * reconnect, pass the replacement client to {@link reattach}: the
 * desired topics re-subscribe and their gates re-baseline.
 */
export class SubscriptionManager {
	private client: TightbeamWsClient;

	private readonly entries = new Map<string, Entry>();

	private readonly fallback: MuxStreamHandler | undefined;

	constructor(client: TightbeamWsClient, options?: ManagerOptions) {
		this.client = client;
		this.fallback = options?.fallback;
		this.install();
	}

	/**
	 * The topics currently subscribed (or awaiting reattach).
	 */
	get topics(): readonly string[] {
		return [...this.entries.keys()];
	}

	/**
	 * Subscribe to `topic`, resolving once the server acknowledges.
	 *
	 * The dispatch entry registers before the command leaves, so an
	 * update racing the acknowledgment still routes. A refusal
	 * (`PermissionDenied`, `Unavailable`, ...) removes the entry and
	 * rethrows. A connection loss keeps the topic in the desired set
	 * with a `pending` state: delivery starts after {@link reattach}.
	 *
	 * @throws TypeError for an invalid topic name, Error when already
	 * subscribed.
	 */
	async subscribe<T>(
		topic: string,
		options: SubscribeOptions<T>,
	): Promise<Subscription<T>> {
		assertTopic(topic);
		if (this.entries.has(topic)) {
			throw new Error(`already subscribed to topic: ${topic}`);
		}

		const { entry, channel } = buildEntry(topic, options);
		this.entries.set(topic, entry);

		try {
			await this.command(SUB_PREFIX, topic);
			entry.state = "live";
		} catch (error) {
			if (!isConnectionLoss(error)) {
				this.entries.delete(topic);
				entry.finishIteration?.();
				throw error;
			}
		}

		return this.handleOf(topic, entry, channel);
	}

	/**
	 * Publish `message` on `topic` through the wire's `pub/<topic>`
	 * command, resolving once the server acknowledges.
	 *
	 * A {@link MessageCodec} encodes the message directly as the
	 * command's body. An {@link Envelope} publishes frame-in-frame: the
	 * message travels as a full inner frame with the envelope's declared
	 * layers applied, which the registry relays byte-for-byte.
	 *
	 * The server must enable client publish (a `PublishPolicy` on its
	 * `PubsubCommands`); otherwise the command falls through to its
	 * application routes and typically rejects `Unimplemented`.
	 */
	async publish<T>(
		topic: string,
		message: T,
		shape: MessageCodec<T> | Envelope<T>,
	): Promise<void> {
		assertTopic(topic);

		const command = frame().withId(`${PUB_PREFIX}${topic}`);
		let built: Frame;
		if (shape instanceof Envelope) {
			const inner = await shape.frame(message).build();
			built = await command.withMessage(Framed, inner).build();
		} else {
			built = await command.withMessage(shape, message).build();
		}

		await this.client.emit(built);
	}

	/**
	 * Emit `unsub/<topic>` and stop dispatching the topic locally.
	 *
	 * Local removal happens first, so no update dispatches after this
	 * call regardless of the command's fate. A connection loss counts
	 * as done: a dropped connection has no subscriptions.
	 */
	async unsubscribe(topic: string): Promise<void> {
		const entry = this.entries.get(topic);
		if (entry === undefined) {
			return;
		}
		this.entries.delete(topic);
		entry.finishIteration?.();

		try {
			await this.command(UNSUB_PREFIX, topic);
		} catch (error) {
			if (!isConnectionLoss(error)) {
				throw error;
			}
		}
	}

	/**
	 * Resume on a replacement connection after the previous one closed:
	 * install the serve handler, reset every gate (the registry's stamps
	 * are per-topic, not per-connection, so the next update
	 * re-baselines), and replay the `sub/` commands for every desired
	 * topic.
	 */
	async reattach(client: TightbeamWsClient): Promise<void> {
		this.client = client;
		this.install();

		const replays: Promise<void>[] = [];
		for (const [topic, entry] of this.entries) {
			entry.gate.reset();
			entry.state = "pending";
			replays.push(this.resubscribe(topic, entry));
		}
		await Promise.all(replays);
	}

	/**
	 * Replay one `sub/` command, going live on acknowledgment. Another
	 * connection loss keeps the topic pending for the next reattach.
	 */
	private async resubscribe(topic: string, entry: Entry): Promise<void> {
		try {
			await this.command(SUB_PREFIX, topic);
			entry.state = "live";
		} catch (error) {
			if (!isConnectionLoss(error)) {
				throw error;
			}
		}
	}

	/**
	 * The consumer-facing handle over one entry.
	 */
	private handleOf<T>(
		topic: string,
		entry: Entry,
		channel: PullChannel<Update<T>> | undefined,
	): Subscription<T> {
		const entries = this.entries;
		const subscription: Subscription<T> = {
			topic,
			get state(): SubscriptionState {
				const current = entries.get(topic);
				if (current !== entry) {
					return "ended";
				}
				return entry.state;
			},
			unsubscribe: async (): Promise<void> => {
				await this.unsubscribe(topic);
			},
			[Symbol.asyncIterator](): AsyncIterator<Update<T>> {
				if (channel === undefined) {
					throw new Error(
						"this subscription delivers through onUpdate; " +
							"omit the handler to iterate instead",
					);
				}
				return {
					next: (): Promise<IteratorResult<Update<T>>> => {
						return channel.next();
					},
				};
			},
		};
		return subscription;
	}

	/**
	 * Register the dispatch handler on the current client, claiming
	 * dispatch exclusively so a later `client.serve` cannot silently
	 * unroute updates.
	 */
	private install(): void {
		this.client.serve(
			async (update) => {
				const routed = await this.dispatch(update);
				return routed;
			},
			{ exclusive: true },
		);
	}

	/**
	 * Emit one command stream (`sub/` or `unsub/`) for `topic`.
	 */
	private async command(prefix: string, topic: string): Promise<void> {
		const built = await frame(EMPTY_BODY)
			.withId(`${prefix}${topic}`)
			.build();
		await this.client.emit(built);
	}

	/**
	 * Route one server-initiated stream.
	 */
	private async dispatch(update: Frame): Promise<Frame | undefined | null> {
		const id = TEXT.decode(update.id);
		if (id.startsWith(END_PREFIX)) {
			const completed = this.complete(id.slice(END_PREFIX.length));
			if (completed) {
				return undefined;
			}
			return this.unmatched(update, id);
		}

		const entry = this.entries.get(id);
		if (entry === undefined) {
			return this.unmatched(update, id);
		}

		await this.admit(id, entry, update);
		return undefined;
	}

	/**
	 * Gate one update, handling a revealed gap, then deliver it.
	 */
	private async admit(
		topic: string,
		entry: Entry,
		update: Frame,
	): Promise<void> {
		const expected = entry.gate.expected;
		const verdict = entry.gate.admit(update.order);
		if (verdict === "stale") {
			return;
		}

		if (verdict === "gap" && expected !== undefined) {
			await this.reportGap(topic, entry, expected, update.order);
		}
		await entry.deliver(update);
	}

	/**
	 * Run the subscription's gap observer, or the default resync: re-emit
	 * the `sub/` command (idempotent on the Stage A server; a
	 * replay-capable one can use it to resync). A connection loss during
	 * the resync defers to reattach.
	 */
	private async reportGap(
		topic: string,
		entry: Entry,
		expected: bigint,
		received: bigint,
	): Promise<void> {
		if (entry.onGap !== undefined) {
			await entry.onGap(topic, expected, received);
			return;
		}

		try {
			await this.command(SUB_PREFIX, topic);
		} catch (error) {
			if (!isConnectionLoss(error)) {
				throw error;
			}
		}
	}

	/**
	 * Complete one topic: remove the entry, end its iteration, and
	 * notify its observer.
	 */
	private complete(topic: string): boolean {
		const entry = this.entries.get(topic);
		if (entry === undefined) {
			return false;
		}

		this.entries.delete(topic);
		entry.finishIteration?.();
		entry.onEnd?.(topic);
		return true;
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

/**
 * The typed decode step one subscription applies to each update frame:
 * a direct codec decode, or a frame-in-frame unwrap under the envelope's
 * declared layers.
 */
function decoderOf<T>(
	options: SubscribeOptions<T>,
): (update: Frame) => T | Promise<T> {
	const layered = options.envelope;
	if (layered !== undefined) {
		const unwrap = (update: Frame): Promise<T> => {
			const inner = update.message(Framed);
			return layered.unwrap(inner);
		};
		return unwrap;
	}

	const codec = options.codec;
	const decode = (update: Frame): T => {
		return update.message(codec);
	};
	return decode;
}

/**
 * Assemble one topic's dispatch entry: handler mode delivers through
 * `onUpdate`; iterator mode parks each update on the pull channel until
 * the consumer takes it, so iteration back-pressures the server exactly
 * like a slow handler.
 */
function buildEntry<T>(
	topic: string,
	options: SubscribeOptions<T>,
): { entry: Entry; channel: PullChannel<Update<T>> | undefined } {
	const decode = decoderOf(options);
	const onUpdate = options.onUpdate;
	if (onUpdate !== undefined) {
		const deliver = async (update: Frame): Promise<void> => {
			const message = await decode(update);
			await onUpdate(message, update, topic);
		};

		const entry: Entry = {
			gate: new TopicGate(),
			deliver,
			finishIteration: undefined,
			onGap: options.onGap,
			onEnd: options.onEnd,
			state: "pending",
		};

		return { entry, channel: undefined };
	}

	const channel = new PullChannel<Update<T>>();
	const deliver = async (update: Frame): Promise<void> => {
		const message = await decode(update);
		await channel.put({ message, frame: update, topic });
	};

	const entry: Entry = {
		gate: new TopicGate(),
		deliver,
		finishIteration: (): void => {
			channel.finish();
		},
		onGap: options.onGap,
		onEnd: options.onEnd,
		state: "pending",
	};

	return { entry, channel };
}
