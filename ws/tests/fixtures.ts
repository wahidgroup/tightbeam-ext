/**
 * The fixtures of the ws e2e lanes, their pages, and the pubsub suites, as `docs/ws.md` (Test support) states them.
 */

import type {
	CleartextConnectOptions,
	ConnectOptions,
	Engine,
	Frame,
	MutualConnectOptions,
	SharedKey,
	TightbeamWsClient,
} from "@wahidgroup/tightbeam-ws-client";

const ENCODER = new TextEncoder();

/**
 * The stack fact that sets the stream cap of each echo server.
 */
const STREAMS = "MUX_STREAMS";

/**
 * The stack fact that holds the payment that settles the demo invoice.
 */
const PAYMENT = "TBWS_DEMO_PAYMENT";

/**
 * The stack fact that sets the client-to-server credit ceiling.
 */
const BUDGET_C2S = "TBWS_MUX_BUDGET_C2S";

/**
 * The stack fact that sets the server-to-client credit ceiling.
 */
const BUDGET_S2C = "TBWS_MUX_BUDGET_S2C";

/**
 * The stack facts one source holds, by the name the stack writes each under:
 * the environment of a Node lane, or the query string of a page.
 */
export class StackFacts {
	readonly #read: (name: string) => string | undefined;

	readonly #origin: string;

	private constructor(read: (name: string) => string | undefined, origin: string) {
		this.#read = read;
		this.#origin = origin;
	}

	/**
	 * The facts that `read` answers, which answers `undefined` for a fact it
	 * does not hold. `origin` names the source in a refusal.
	 */
	static over(read: (name: string) => string | undefined, origin: string): StackFacts {
		const facts = new StackFacts(read, origin);
		return facts;
	}

	/**
	 * The facts in the query string `search` of a page, which a spec fills
	 * with the facts of its stack.
	 */
	static fromQuery(search: string): StackFacts {
		const params = new URLSearchParams(search);
		const read = (name: string): string | undefined => params.get(name) ?? undefined;

		const facts = new StackFacts(read, "the page query");
		return facts;
	}

	/**
	 * The text of the fact `name`.
	 *
	 * @throws Error when the source holds no such fact.
	 */
	text(name: string): string {
		const text = this.#read(name);
		if (text === undefined) {
			throw new Error(`${this.#origin} holds no ${name}`);
		}

		return text;
	}

	/**
	 * The whole number that the fact `name` spells in decimal digits, up to
	 * `Number.MAX_SAFE_INTEGER`.
	 *
	 * @throws Error when the fact is absent, or holds any other text.
	 */
	count(name: string): number {
		const text = this.text(name);
		const count = Number(text);
		const whole = /^\d+$/.test(text) && Number.isSafeInteger(count);
		if (!whole) {
			const shown = JSON.stringify(text);
			throw new Error(`${name} holds ${shown}, which is not a whole number`);
		}

		return count;
	}
}

/**
 * The demo paywall that `ws/scripts/stack-env.sh` writes and the paywalled
 * servers read: the payment that settles the demo invoice, and the credit
 * ceiling of each direction.
 */
export class StackPaywall {
	/**
	 * The payment that settles the demo invoice.
	 */
	readonly payment: string;

	/**
	 * The credit ceiling of each direction, which a mutual dial requests.
	 */
	readonly budgets: NonNullable<MutualConnectOptions["budgets"]>;

	private constructor(payment: string, budgets: NonNullable<MutualConnectOptions["budgets"]>) {
		this.payment = payment;
		this.budgets = budgets;
	}

	/**
	 * The paywall that `facts` hold.
	 */
	static read(facts: StackFacts): StackPaywall {
		const payment = facts.text(PAYMENT);
		const clientToServer = facts.count(BUDGET_C2S);
		const serverToClient = facts.count(BUDGET_S2C);

		const paywall = new StackPaywall(payment, {
			clientToServer,
			serverToClient,
		});
		return paywall;
	}

	/**
	 * Mutual dial options that request the ceiling of this paywall and settle
	 * the first `payments` invoices, at the handshake and at each renewal,
	 * with its payment.
	 */
	sessionOptions(payments = 1024): MutualConnectOptions {
		const payment = ENCODER.encode(this.payment);
		let left = payments;
		const options = {
			budgets: this.budgets,
			approveReceipt: (): Uint8Array | undefined => {
				if (left <= 0) {
					return undefined;
				}

				left -= 1;

				return payment;
			},
		};
		return options;
	}

	/**
	 * Each fact of this paywall as text under its own name.
	 */
	params(): Record<string, string> {
		const params = {
			[PAYMENT]: this.payment,
			[BUDGET_C2S]: String(this.budgets.clientToServer),
			[BUDGET_S2C]: String(this.budgets.serverToClient),
		};
		return params;
	}
}

/**
 * The stack facts that a client dials with: the stream cap that a cleartext
 * dial passes, because no handshake negotiates it, and the paywall that a
 * mutual dial requests the ceiling of and pays.
 */
export class DialFacts {
	/**
	 * The stream cap of each echo server, which a cleartext dial passes.
	 */
	readonly streams: number;

	/**
	 * The demo paywall of the mutual echo server.
	 */
	readonly paywall: StackPaywall;

	private constructor(streams: number, paywall: StackPaywall) {
		this.streams = streams;
		this.paywall = paywall;
	}

	/**
	 * The dial facts that `facts` hold.
	 */
	static read(facts: StackFacts): DialFacts {
		const streams = facts.count(STREAMS);
		const paywall = StackPaywall.read(facts);

		const dial = new DialFacts(streams, paywall);
		return dial;
	}

	/**
	 * The dial facts in the query string `search` of a page.
	 */
	static fromQuery(search: string): DialFacts {
		const dial = DialFacts.read(StackFacts.fromQuery(search));
		return dial;
	}

	/**
	 * The options of a cleartext dial, which pass the stream cap of the stack
	 * because no handshake negotiates it.
	 */
	get cleartext(): CleartextConnectOptions {
		const options = { streams: this.streams };
		return options;
	}

	/**
	 * Each fact as text under its own name, for the query string of a page
	 * that reads it back through {@link fromQuery}.
	 */
	params(): Record<string, string> {
		const params = {
			[STREAMS]: String(this.streams),
			...this.paywall.params(),
		};
		return params;
	}
}

/**
 * The echo servers of a stack that a Node lane dials, and the certificate
 * that the encrypted ones present.
 */
export interface EchoServers {
	/**
	 * The multiplexed encrypted echo server.
	 */
	readonly muxEndpoint: string;

	/**
	 * The multiplexed cleartext echo server.
	 */
	readonly muxClearEndpoint: string;

	/**
	 * The cleartext duplex echo server.
	 */
	readonly muxDuplexEndpoint: string;

	/**
	 * The dial facts of the stack.
	 */
	readonly dial: DialFacts;

	/**
	 * The DER certificate of the encrypted servers, which a dial pins.
	 */
	readonly serverCertDer: Uint8Array;
}

/**
 * One multiplexed lane of the echo servers, by name, for a table of cases.
 */
export interface EchoLane {
	/**
	 * The name of the lane, `encrypted` or `cleartext`.
	 */
	readonly lane: "encrypted" | "cleartext";

	/**
	 * Dial the echo server of the lane under `options`.
	 */
	readonly connect: (options?: ConnectOptions) => Promise<TightbeamWsClient>;
}

/**
 * The dials of the Node lanes against the echo servers of a stack, through
 * one engine.
 */
export class EchoDials {
	readonly #engine: Engine;

	readonly #servers: EchoServers;

	private constructor(engine: Engine, servers: EchoServers) {
		this.#engine = engine;
		this.#servers = servers;
	}

	/**
	 * The dials of `servers` through `engine`.
	 */
	static of(engine: Engine, servers: EchoServers): EchoDials {
		const dials = new EchoDials(engine, servers);
		return dials;
	}

	/**
	 * Both multiplexed lanes, which behave alike above the transport.
	 */
	get lanes(): readonly EchoLane[] {
		const lanes: readonly EchoLane[] = [
			{
				lane: "encrypted",
				connect: (options) => this.encrypted(options),
			},
			{
				lane: "cleartext",
				connect: (options) => this.cleartext(options),
			},
		];
		return lanes;
	}

	/**
	 * Dial the encrypted echo server, which the dial pins.
	 */
	encrypted(options?: ConnectOptions): Promise<TightbeamWsClient> {
		const servers = this.#servers;
		const dialing = this.#engine.connect(servers.muxEndpoint, servers.serverCertDer, options);
		return dialing;
	}

	/**
	 * Dial the cleartext echo server under the stream cap of the stack.
	 */
	cleartext(options?: ConnectOptions): Promise<TightbeamWsClient> {
		const servers = this.#servers;
		const dialing = this.#engine.connectCleartext(servers.muxClearEndpoint, {
			...options,
			...servers.dial.cleartext,
		});
		return dialing;
	}

	/**
	 * Dial the duplex echo server, which answers each chunk with the same
	 * octets.
	 */
	duplex(): Promise<TightbeamWsClient> {
		const servers = this.#servers;
		const dialing = this.#engine.connectCleartext(servers.muxDuplexEndpoint, servers.dial.cleartext);
		return dialing;
	}

	/**
	 * Emit `built` on `client` and return the response frame, which the round
	 * trip MUST receive. A page calls it as a Node lane does.
	 *
	 * @throws Error when the peer returns no response frame.
	 */
	static async emitOrFail(client: EmitClient, built: Frame): Promise<Frame> {
		const response = await client.emit(built);
		if (response === undefined) {
			throw new Error("the peer returned no response frame");
		}

		return response;
	}
}

/**
 * The route that the progressive echo stamps on the id of its answer,
 * `routed:<target>:<hops>`, as `docs/ws.md` (Demo servers) states it. It takes
 * the shape of the `StreamRoute` that a `serve*` handler reads.
 */
export class EchoedRoute {
	/**
	 * The servlet URN that the Open named, or `undefined` for an unrouted Open.
	 */
	readonly target: string | undefined;

	/**
	 * The hop budget that the Open carried.
	 */
	readonly hopsRemaining: number;

	private constructor(target: string | undefined, hopsRemaining: number) {
		this.target = target;
		this.hopsRemaining = hopsRemaining;
	}

	/**
	 * The route that the echoed frame id `id` names.
	 *
	 * @throws Error when `id` holds no echoed route.
	 */
	static of(id: string): EchoedRoute {
		const stamp = /^routed:(.*):(\d+)$/.exec(id);
		if (stamp === null) {
			throw new Error(`${JSON.stringify(id)} holds no echoed route`);
		}

		const [, named = "", hops = ""] = stamp;
		let target: string | undefined;
		if (named !== "") {
			target = named;
		}

		const route = new EchoedRoute(target, Number(hops));
		return route;
	}
}

/**
 * The AES-256-GCM key-encryption key of the sealed round trips, and the
 * identifier that names it in each sealed body.
 */
export const SEAL_SECRET: SharedKey = {
	key: new Uint8Array(32).fill(7),
	keyId: ENCODER.encode("tbws/e2e/kek/v1"),
};

/**
 * A note: its author and its text, the typed message that the suites
 * round-trip.
 */
export interface Note {
	/**
	 * Who wrote the note.
	 */
	readonly author: string;

	/**
	 * What the note says.
	 */
	readonly text: string;
}

/**
 * The JSON payload of a {@link Note}. A suite lifts it into a body codec with
 * `engine.wrapping`, as the client unit tests do.
 */
export const NotePayload = {
	/**
	 * The JSON octets of `note`.
	 */
	encode(note: Note): Uint8Array {
		const json = JSON.stringify(note);
		const payload = ENCODER.encode(json);
		return payload;
	},

	/**
	 * The note that the JSON octets of `payload` hold.
	 *
	 * @throws TypeError when the payload is no note.
	 */
	decode(payload: Uint8Array): Note {
		const json = new TextDecoder().decode(payload);
		const parsed: unknown = JSON.parse(json);
		if (
			typeof parsed !== "object" ||
			parsed === null ||
			!("author" in parsed) ||
			!("text" in parsed) ||
			typeof parsed.author !== "string" ||
			typeof parsed.text !== "string"
		) {
			throw new TypeError("a note needs a string author and text");
		}

		const note = { author: parsed.author, text: parsed.text };
		return note;
	},
} as const;

/**
 * Hex for fixture bytes, as the browser apps and the pubsub suites read it.
 */
export { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

/**
 * The emit surface shared by the cleartext, encrypted, and multiplexed
 * clients.
 */
export interface EmitClient {
	/**
	 * Emit `frame` and resolve with the response frame, if the peer sent one.
	 */
	emit(frame: Frame): Promise<Frame | undefined>;
}
