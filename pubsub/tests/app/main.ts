/**
 * Live board example app for the pubsub extension.
 *
 * Connects over mutual-auth ECIES to the demo server named in the
 * `endpoint` query parameter (pinning `cert`, presenting `clientCert` /
 * `clientKey`, paying the demo session-budget invoice), subscribes to
 * the `topic` query parameter, and renders every update into the DOM as
 * it arrives.
 *
 * Every message travels as a full tightbeam frame under a typed
 * {@link Envelope}: the envelope declares the layers once (signed by
 * the publisher, sealed with `seal=1`) and both builds outgoing frames
 * and unwraps received ones, enforcing the declarations. On the
 * processed board (`processed=1`) the backend servlet rebuilds the
 * frame, so receiving declares the servlet's seal and no signature.
 * Each rendered item carries `data-verified` and `data-sealed` badges
 * from the receiving envelope's declarations, which `unwrap` proved.
 */

import type {
	Envelope,
	Frame,
	MessageCodec,
} from "@wahidgroup/tightbeam-ws-client";
import {
	Aes256Gcm,
	Secp256k1SigningKey,
	TightbeamWsClient,
	envelope,
	wrapped,
} from "@wahidgroup/tightbeam-ws-client";
import { SubscriptionManager } from "@wahidgroup/tightbeam-pubsub-client";

const ENCODER = new TextEncoder();

const DECODER = new TextDecoder();

/**
 * The publisher's signing identity. A fixed demo scalar: the subscriber
 * page derives the same verifying key to check authenticity end to end.
 */
const PUBLISHER_KEY = Secp256k1SigningKey.fromBytes(new Uint8Array(32).fill(1));

/**
 * The pre-shared AES-256-GCM key: the topic seal on sealed boards
 * (`seal=1`), and the key the processor servlet seals rebuilt frames
 * under (`processed=1`).
 */
const TOPIC_KEY = new Uint8Array(32).fill(7);

/**
 * The typed message every note board publishes.
 */
interface Note {
	author: string;
	text: string;
}

/**
 * Runtime-validate a decoded note.
 */
function asNote(value: unknown): Note {
	if (typeof value !== "object" || value === null) {
		throw new Error("a note must be a JSON object");
	}
	if (!("author" in value) || !("text" in value)) {
		throw new Error("a note needs author and text");
	}

	const { author, text } = value;
	if (typeof author !== "string" || typeof text !== "string") {
		throw new Error("a note needs string author and text");
	}

	return { author, text };
}

/**
 * The typed body codec: JSON in the profile opaque wrapper.
 */
const Notes: MessageCodec<Note> = wrapped({
	encode(note: Note): Uint8Array {
		return ENCODER.encode(JSON.stringify(note));
	},
	decode(payload: Uint8Array): Note {
		return asNote(JSON.parse(DECODER.decode(payload)));
	},
});

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
 * Decode a base64 DER / key query parameter.
 */
function bytesFromParam(encoded: string): Uint8Array {
	const binary = atob(encoded);
	const bytes = new Uint8Array(binary.length);
	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}

	return bytes;
}

/**
 * Demo settlement payment matching `tightbeam_ws::testing::DEMO_PAYMENT`.
 */
const DEMO_PAYMENT = new TextEncoder().encode("tbws-demo-payment-v1");

/**
 * The envelope this page publishes under: always signed, sealed when
 * the board runs sealed.
 */
function publishEnvelope(seal: boolean): Envelope<Note> {
	const signed = envelope(Notes).signed(PUBLISHER_KEY);
	if (seal) {
		return signed.sealed(Aes256Gcm.fromKey(TOPIC_KEY));
	}

	return signed;
}

/**
 * The envelope this page receives under. The plain board expects its
 * own publishes back untouched. The processed board expects the
 * servlet's rebuild: sealed under the pre-shared key and unsigned.
 */
function receiveEnvelope(seal: boolean, processed: boolean): Envelope<Note> {
	if (processed) {
		return envelope(Notes).sealed(Aes256Gcm.fromKey(TOPIC_KEY));
	}

	return publishEnvelope(seal);
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

	await manager.publish(topic, { author: "board", text }, publishing);
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
	const publishing = publishEnvelope(seal);
	const receiving = receiveEnvelope(seal, processed);

	const client = await TightbeamWsClient.connectMutual(
		endpoint,
		bytesFromParam(cert),
		bytesFromParam(clientCert),
		bytesFromParam(clientKey),
		{
			budgets: { clientToServer: 4096, serverToClient: 4096 },
			approveReceipt: (): Uint8Array => DEMO_PAYMENT,
		},
	);

	const manager = new SubscriptionManager(client);
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
