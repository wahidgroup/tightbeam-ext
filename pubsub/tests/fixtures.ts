/**
 * Fixtures of the pubsub e2e stack that the board page and the Node suites share, so each runs in the browser.
 * The fixtures that the ws stack owns come from `#ws-fixtures`.
 */

import type {
	Aes256Gcm,
	Envelope,
	MutualIdentity,
	Secp256k1SigningKey,
	SharedKey,
} from "@wahidgroup/tightbeam-ws-client";

import type { Note } from "#ws-fixtures";
import { DialFacts, StackFacts, bytesToHex, hexToBytes } from "#ws-fixtures";
import { base64ToBytes } from "#ws-util";

/**
 * The stack fact that spells the key of the topic seal in hex.
 */
const TOPIC_KEY = "PUBSUB_TOPIC_KEY";

/**
 * The stack fact that names the key of the topic seal in each sealed
 * envelope.
 */
const TOPIC_KEY_ID = "PUBSUB_TOPIC_KEY_ID";

/**
 * The pre-shared AES-256-GCM key of the topic seal and its identifier, from
 * `pubsub/scripts/stack-env.sh`: the seal of the sealed boards and frames,
 * and the key the processor servlet seals each rebuilt frame under.
 */
export class TopicSecret {
	readonly shared: SharedKey;

	private constructor(shared: SharedKey) {
		this.shared = shared;
	}

	/**
	 * The topic seal that `facts` hold.
	 */
	static read(facts: StackFacts): TopicSecret {
		const key = hexToBytes(facts.text(TOPIC_KEY));
		const keyId = new TextEncoder().encode(facts.text(TOPIC_KEY_ID));

		const secret = new TopicSecret({ key, keyId });
		return secret;
	}

	/**
	 * Each fact of the seal as text under its own name, for the query string
	 * of a page that reads it back through {@link read}.
	 */
	params(): Record<string, string> {
		const params = {
			[TOPIC_KEY]: bytesToHex(this.shared.key),
			[TOPIC_KEY_ID]: new TextDecoder().decode(this.shared.keyId),
		};
		return params;
	}
}

/**
 * The topics of one suite run. Every connection of a run shares the
 * registry of a demo server, so each test names its topic under the run.
 */
export class TopicRun {
	/**
	 * The run of this module instance.
	 */
	static readonly current = new TopicRun(Math.random().toString(36).slice(2, 10));

	readonly #run: string;

	private constructor(run: string) {
		this.#run = run;
	}

	/**
	 * The topic `name` of this run.
	 */
	topic(name: string): string {
		const topic = `e2e/${this.#run}/${name}`;
		return topic;
	}

	/**
	 * The topic `name` of this run under `forbidden/`, which every demo
	 * server refuses to subscribe or publish.
	 */
	forbidden(name: string): string {
		const topic = `forbidden/${this.#run}/${name}`;
		return topic;
	}
}

/**
 * Every board mode, which the page parses its query against.
 */
const BOARD_MODES = ["sealed", "processed"] as const;

/**
 * How a board publishes and receives its notes:
 *
 * - `sealed`: signed, and sealed under the topic seal, both ways.
 * - `processed`: published signed, and received as the processor servlet
 *   rebuilds it, sealed and unsigned.
 */
export type BoardMode = (typeof BOARD_MODES)[number];

/**
 * The envelopes of one board: the one its notes publish under, and the one
 * each delivered inner frame unwraps under.
 */
interface BoardEnvelopes {
	readonly publishing: Envelope<Note, true, boolean>;

	readonly receiving: Envelope<Note, boolean, true>;
}

/**
 * The query parameter of each value of a board that is not a stack fact.
 */
const BOARD_PARAMS = {
	endpoint: "endpoint",
	topic: "topic",
	mode: "mode",
	serverCert: "cert",
	clientCert: "clientCert",
	clientKey: "clientKey",
} as const;

/**
 * The identity a board dials with, each value in base64 as the query string
 * carries it.
 */
export interface BoardIdentity {
	readonly serverCertDer: string;
	readonly clientCertDer: string;
	readonly clientKey: string;
}

/**
 * Everything a board page reads from its query string: the demo server and
 * the identity it dials with, the topic and the mode of the board, and the
 * stack facts it dials and seals under. A spec writes the query through
 * {@link search}, and the page reads it back through {@link fromQuery}.
 */
export class BoardQuery {
	readonly endpoint: string;

	readonly topic: string;

	readonly #mode: BoardMode;

	readonly identity: BoardIdentity;

	readonly dial: DialFacts;

	readonly secret: TopicSecret;

	constructor(fields: {
		readonly endpoint: string;
		readonly topic: string;
		readonly mode: BoardMode;
		readonly identity: BoardIdentity;
		readonly dial: DialFacts;
		readonly secret: TopicSecret;
	}) {
		this.endpoint = fields.endpoint;
		this.topic = fields.topic;
		this.#mode = fields.mode;
		this.identity = fields.identity;
		this.dial = fields.dial;
		this.secret = fields.secret;
	}

	/**
	 * The board that the query string `search` of a page names.
	 *
	 * @throws Error when the query lacks a value, or names no board mode.
	 */
	static fromQuery(search: string): BoardQuery {
		const facts = StackFacts.fromQuery(search);
		const named = facts.text(BOARD_PARAMS.mode);
		const mode = BOARD_MODES.find((known) => known === named);
		if (mode === undefined) {
			throw new Error(`the page query names no board mode: ${named}`);
		}

		const query = new BoardQuery({
			endpoint: facts.text(BOARD_PARAMS.endpoint),
			topic: facts.text(BOARD_PARAMS.topic),
			mode,
			identity: {
				serverCertDer: facts.text(BOARD_PARAMS.serverCert),
				clientCertDer: facts.text(BOARD_PARAMS.clientCert),
				clientKey: facts.text(BOARD_PARAMS.clientKey),
			},
			dial: DialFacts.read(facts),
			secret: TopicSecret.read(facts),
		});
		return query;
	}

	/**
	 * The envelopes of this board over `notes`. Each board signs with
	 * `publisherKey`. The sealed board seals under the topic `cipher` both
	 * ways, and the processed board receives the rebuild of the servlet,
	 * sealed under `cipher` and unsigned.
	 */
	envelopes(notes: Envelope<Note>, cipher: Aes256Gcm, publisherKey: Secp256k1SigningKey): BoardEnvelopes {
		const signed = notes.signed({
			signer: publisherKey,
			verifier: publisherKey.verifyingKey(),
		});

		switch (this.#mode) {
			case "sealed": {
				const sealed = signed.sealed({
					sealer: cipher,
					opener: cipher,
				});
				const envelopes = { publishing: sealed, receiving: sealed };
				return envelopes;
			}
			case "processed": {
				const rebuilt = notes.sealed({ opener: cipher });
				const envelopes = { publishing: signed, receiving: rebuilt };
				return envelopes;
			}
		}
	}

	/**
	 * The identity of the board as the mutual dial takes it.
	 */
	mutualIdentity(): MutualIdentity {
		const identity = {
			serverCertDer: base64ToBytes(this.identity.serverCertDer),
			clientCertDer: base64ToBytes(this.identity.clientCertDer),
			clientKey: base64ToBytes(this.identity.clientKey),
		};
		return identity;
	}

	/**
	 * The query string that {@link fromQuery} reads back as this board,
	 * with its leading `?`.
	 */
	search(): string {
		const params = new URLSearchParams({
			[BOARD_PARAMS.endpoint]: this.endpoint,
			[BOARD_PARAMS.topic]: this.topic,
			[BOARD_PARAMS.mode]: this.#mode,
			[BOARD_PARAMS.serverCert]: this.identity.serverCertDer,
			[BOARD_PARAMS.clientCert]: this.identity.clientCertDer,
			[BOARD_PARAMS.clientKey]: this.identity.clientKey,
			...this.dial.params(),
			...this.secret.params(),
		});

		const search = `?${params.toString()}`;
		return search;
	}
}
