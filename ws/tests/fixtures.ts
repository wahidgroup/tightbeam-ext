/**
 * Fixtures shared by every lane of the ws e2e stack and by the pubsub suites,
 * which import this module as `#ws-fixtures`:
 *
 * - The readers of the stack facts a client dials with, under their own
 *   names, from the environment or the query string of a page.
 * - The mutual dial options over the demo paywall, the sealed round-trip key,
 *   and the typed note payload, which a suite wraps with the codecs of its
 *   engine. The note payload lives with the client unit tests.
 * - Byte codecs, with hex from `@noble/hashes`, and client lifecycle helpers.
 *
 * The module reads no environment and imports no Node module, so the browser
 * apps import it as the Node lanes do.
 */

import type {
	Frame,
	MutualConnectOptions,
	SharedKey,
} from "@wahidgroup/tightbeam-ws-client";

const ENCODER = new TextEncoder();

/**
 * The stack fact that sets the stream cap of every demo server.
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
 * A source of stack facts: it answers the text of each fact by the name the
 * stack writes it under, and throws for a fact it does not hold. A Node lane
 * reads the environment, and a page reads its query string.
 */
export type FactSource = (name: string) => string;

/**
 * The demo paywall that `ws/scripts/stack-env.sh` writes and the paywalled
 * servers read: the payment that settles the demo invoice, and the credit
 * ceiling of each direction.
 */
export interface StackPaywall {
	readonly payment: string;
	readonly budgets: NonNullable<MutualConnectOptions["budgets"]>;
}

/**
 * The stack facts that a client dials with: the stream cap that a cleartext
 * dial passes, because no handshake negotiates it, and the paywall that a
 * mutual dial requests the ceiling of and pays.
 */
export interface DialFacts {
	readonly streams: number;
	readonly paywall: StackPaywall;
}

/**
 * The whole number that `text`, the value of the stack fact `name`, spells
 * in decimal digits. Any other text throws, as the Rust `EnvVar::parsed`
 * refuses it, so a malformed fact never reaches a dial as `NaN`.
 */
export function parseCount(name: string, text: string): number {
	const count = Number(text);
	const whole = /^\d+$/.test(text) && Number.isSafeInteger(count);
	if (!whole) {
		const shown = JSON.stringify(text);
		throw new Error(`${name} holds ${shown}, which is not a whole number`);
	}

	return count;
}

/**
 * The dial facts that `source` holds.
 */
export function readDialFacts(source: FactSource): DialFacts {
	const streams = parseCount(STREAMS, source(STREAMS));
	const payment = source(PAYMENT);
	const clientToServer = parseCount(BUDGET_C2S, source(BUDGET_C2S));
	const serverToClient = parseCount(BUDGET_S2C, source(BUDGET_S2C));

	const paywall = { payment, budgets: { clientToServer, serverToClient } };
	const facts = { streams, paywall };
	return facts;
}

/**
 * Each fact of `facts` as text under its own name, for the query string of
 * a page that reads it back through {@link readDialFacts}.
 */
export function dialFactParams(facts: DialFacts): Record<string, string> {
	const { clientToServer, serverToClient } = facts.paywall.budgets;
	const params = {
		[STREAMS]: String(facts.streams),
		[PAYMENT]: facts.paywall.payment,
		[BUDGET_C2S]: String(clientToServer),
		[BUDGET_S2C]: String(serverToClient),
	};
	return params;
}

/**
 * The fact source over the query string `search` of a page, which a spec
 * fills with the facts of its `STACK`.
 */
export function queryFacts(search: string): FactSource {
	const params = new URLSearchParams(search);
	const source = (name: string): string => {
		const text = params.get(name);
		if (text === null) {
			throw new Error(`the page has no ${name} query parameter`);
		}

		return text;
	};
	return source;
}

/**
 * Mutual dial options for the compose stack: request the ceiling of
 * `paywall` and settle its invoice with its payment. `payments` caps how many
 * invoices the wallet settles (handshake + renewals), so `0` leaves every
 * invoice unpaid.
 */
export function mutualSessionOptions(
	paywall: StackPaywall,
	payments = 1024,
): MutualConnectOptions {
	const payment = ENCODER.encode(paywall.payment);
	let left = payments;
	const options = {
		budgets: paywall.budgets,
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
 * The AES-256-GCM key-encryption key of the sealed round trips, and the
 * identifier that names it in each sealed body.
 */
export const SEAL_SECRET: SharedKey = {
	key: new Uint8Array(32).fill(7),
	keyId: ENCODER.encode("tbws/e2e/kek/v1"),
};

export type { Note } from "../client/src/testing/notes.js";

/**
 * The JSON payload of a note. A suite lifts it into a body codec with
 * `engine.wrapping`, as the client unit tests do.
 */
export { NotePayload } from "../client/src/testing/notes.js";

/**
 * Hex for fixture bytes, as the browser apps and the pubsub suites read it.
 */
export { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

/**
 * Decode a base64 string, such as a DER or key that crossed the
 * `page.evaluate` boundary or a query parameter, into bytes.
 */
export function base64ToBytes(base64: string): Uint8Array {
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i);
	}

	return bytes;
}

/**
 * The emit surface shared by the cleartext, encrypted, and multiplexed
 * clients.
 */
export interface EmitClient {
	emit(frame: Frame): Promise<Frame | undefined>;
}

/**
 * Open a client via `connect`, run the body, and always close the client,
 * resolving once its socket has closed.
 */
export async function withClient<
	TClient extends { close(): Promise<void> },
	TResult,
>(
	connect: () => Promise<TClient>,
	run: (client: TClient) => Promise<TResult>,
): Promise<TResult> {
	const client = await connect();
	try {
		const result = await run(client);
		return result;
	} finally {
		await client.close();
	}
}

/**
 * Emit `built` and return the response frame. A missing response fails the
 * round-trip.
 */
export async function emitOrFail(
	client: EmitClient,
	built: Frame,
): Promise<Frame> {
	const response = await client.emit(built);
	if (response === undefined) {
		throw new Error("the peer returned no response frame");
	}

	return response;
}
