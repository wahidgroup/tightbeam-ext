/**
 * Browser page that the live and processed board specs drive.
 *
 * The page connects to a demo server over mutual-auth HPKE, pays the demo
 * session-budget invoice, and subscribes to one topic. {@link publishEnvelope}
 * and {@link receiveEnvelope} declare the layers of each direction, and
 * {@link renderUpdate} adds each update to the board.
 *
 * # Query parameters
 *
 * - `endpoint`: the demo server to connect to.
 * - `topic`: the topic to subscribe to and publish on.
 * - `cert`: the server certificate to pin, in base64.
 * - `clientCert`, `clientKey`: the client identity to present, in base64.
 * - The dial facts and the topic seal of the stack, under the names the stack
 *   writes them, which {@link readDialFacts} and {@link readTopicSecret}
 *   parse.
 * - `seal=1`: seal notes under the topic seal.
 * - `processed=1`: receive the frames that the backend servlet rebuilds.
 */

import type {
	Aes256Gcm,
	Envelope,
	Frame,
	Secp256k1SigningKey,
} from "@wahidgroup/tightbeam-ws-client";
import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";
import {
	ClientPorts,
	SubscriptionManager,
} from "@wahidgroup/tightbeam-pubsub-client";

import type { Note } from "#ws-fixtures";
import {
	NotePayload,
	base64ToBytes,
	mutualSessionOptions,
	queryFacts,
	readDialFacts,
} from "#ws-fixtures";
import { readTopicSecret } from "../fixtures.js";

function element<T extends HTMLElement>(id: string): T {
	const found = document.querySelector<T>(`#${id}`);
	if (found === null) {
		throw new Error(`the page is missing #${id}`);
	}

	return found;
}

const status = element("status");
const gapReport = element("gap");
const publishedCount = element("published");
const board = element("board");
const publishForm = element<HTMLFormElement>("publish-form");
const payloadInput = element<HTMLInputElement>("payload");

/**
 * The envelope this page publishes under: `notes` signed, and sealed under
 * the topic `cipher` when the board runs sealed.
 */
function publishEnvelope(
	seal: boolean,
	notes: Envelope<Note>,
	cipher: Aes256Gcm,
	publisherKey: Secp256k1SigningKey,
): Envelope<Note> {
	const signed = notes.signed(publisherKey);
	if (seal) {
		const sealed = signed.sealed(cipher);
		return sealed;
	}

	return signed;
}

/**
 * The envelope this page receives under. The plain board expects its
 * own publishes back untouched. The processed board expects the
 * servlet's rebuild: sealed under the pre-shared topic `cipher` and unsigned.
 */
function receiveEnvelope(
	seal: boolean,
	processed: boolean,
	notes: Envelope<Note>,
	cipher: Aes256Gcm,
	publisherKey: Secp256k1SigningKey,
): Envelope<Note> {
	if (processed) {
		const sealed = notes.sealed(cipher);
		return sealed;
	}

	const published = publishEnvelope(seal, notes, cipher, publisherKey);
	return published;
}

/**
 * Render one unwrapped note: its text, the wrapper's sequence, and the
 * receiving envelope's declarations (which `unwrap` enforced, so the
 * badges are proven properties, not probes).
 */
function renderUpdate(
	note: Note,
	wrapper: Frame,
	receiving: Envelope<Note>,
): void {
	const item = document.createElement("li");
	item.dataset.order = String(wrapper.order);
	item.dataset.verified = String(receiving.authenticated);
	item.dataset.sealed = String(receiving.confidential);
	item.textContent = note.text;
	board.append(item);
}

/**
 * Publish `text` as a typed note under the publishing envelope through
 * the wire's `pub/` command.
 */
async function publish(
	manager: SubscriptionManager,
	topic: string,
	text: string,
	publishing: Envelope<Note>,
): Promise<void> {
	const published = Number(publishedCount.textContent);
	const sequence = published + 1;

	await manager.publish(
		topic,
		{ author: "board", text },
		{ envelope: publishing },
	);

	publishedCount.textContent = String(sequence);
}

async function main(): Promise<void> {
	const params = new URLSearchParams(window.location.search);
	const endpoint = params.get("endpoint");
	const topic = params.get("topic");
	const cert = params.get("cert");
	const clientCert = params.get("clientCert");
	const clientKey = params.get("clientKey");
	if (
		endpoint === null ||
		topic === null ||
		cert === null ||
		clientCert === null ||
		clientKey === null
	) {
		status.textContent =
			"missing endpoint, topic, cert, clientCert, or clientKey query parameter";
		return;
	}

	const seal = params.get("seal") === "1";
	const processed = params.get("processed") === "1";
	const facts = queryFacts(window.location.search);
	const dial = readDialFacts(facts);
	const secret = readTopicSecret(facts);

	const engine = await TightbeamWsClient.init();
	const publisherKey = engine.signingKey(new Uint8Array(32).fill(1));
	const cipher = engine.aes256Gcm(secret);
	const codec = engine.wrapping(NotePayload);
	const notes = engine.envelope(codec);

	const publishing = publishEnvelope(seal, notes, cipher, publisherKey);
	const receiving = receiveEnvelope(
		seal,
		processed,
		notes,
		cipher,
		publisherKey,
	);

	const identity = {
		serverCertDer: base64ToBytes(cert),
		clientCertDer: base64ToBytes(clientCert),
		clientKey: base64ToBytes(clientKey),
	};

	const options = mutualSessionOptions(dial.paywall);
	const client = await engine.connectMutual(endpoint, identity, options);
	const ports = ClientPorts.split(client);
	const manager = new SubscriptionManager(ports);
	await manager.subscribe(topic, {
		envelope: receiving,
		onUpdate: (note, wrapper) => {
			renderUpdate(note, wrapper, receiving);
		},
		onGap: (_gapTopic, expected, received) => {
			gapReport.textContent = `gap: expected ${expected}, received ${received}`;
		},
		onEnd: () => {
			status.textContent = "completed";
		},
	});

	status.textContent = "subscribed";

	publishForm.addEventListener("submit", (event) => {
		event.preventDefault();
		void publish(manager, topic, payloadInput.value, publishing);
	});
}

main().catch((error: unknown) => {
	status.textContent = `error: ${String(error)}`;
});
