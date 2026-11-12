/**
 * Browser page that the live and processed board specs drive.
 *
 * The page connects to a demo server over mutual-auth HPKE, pays the demo
 * session-budget invoice, and subscribes to one topic. Its query string is a
 * {@link BoardQuery}, which the spec writes and the page reads once.
 */

import type { Envelope, Frame } from "@wahidgroup/tightbeam-ws-client";
import { Engine } from "@wahidgroup/tightbeam-ws-client";
import { ClientPorts, SubscriptionManager } from "@wahidgroup/tightbeam-pubsub-client";

import type { Note } from "#ws-fixtures";
import { NotePayload } from "#ws-fixtures";
import { BoardQuery } from "../fixtures.js";

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
 * Render one unwrapped note: its text, the sequence of its wrapper, and
 * whether the inner frame it arrived in carries a signature and a sealed
 * body. Those are properties of the delivered frame, so a frame the servlet
 * rebuilt shows as unsigned whatever the page declared.
 */
function renderUpdate(note: Note, frames: { readonly inner: Frame; readonly wrapper: Frame }): void {
	const { inner, wrapper } = frames;
	const item = document.createElement("li");
	item.dataset.order = String(wrapper.order);
	item.dataset.signed = String(inner.signed);
	item.dataset.sealed = String(inner.confidential);
	item.textContent = note.text;
	board.append(item);
}

/**
 * Publish the `text` of `post` as a typed note on its `topic`, under the
 * publishing envelope, through a `pub/` command.
 */
async function publish(
	manager: SubscriptionManager,
	post: { readonly topic: string; readonly text: string },
	publishing: Envelope<Note, true, boolean>,
): Promise<void> {
	const published = Number(publishedCount.textContent);
	const sequence = published + 1;

	await manager.publish(post.topic, { author: "board", text: post.text }, { envelope: publishing });

	publishedCount.textContent = String(sequence);
}

async function main(): Promise<void> {
	const query = BoardQuery.fromQuery(window.location.search);

	const engine = await Engine.load();
	const publisherKey = engine.signingKey(new Uint8Array(32).fill(1));
	const cipher = engine.aes256Gcm(query.secret.shared);
	const codec = engine.wrapping(NotePayload);
	const notes = engine.envelope(codec);
	const envelopes = query.envelopes(notes, cipher, publisherKey);

	const identity = query.mutualIdentity();
	const options = query.dial.paywall.sessionOptions();
	const client = await engine.connectMutual(query.endpoint, identity, options);
	const ports = ClientPorts.split(client);
	const manager = new SubscriptionManager(ports);

	/*
	 * The board takes each inner frame whole, so it renders what the frame
	 * carries, then unwraps it under the receiving envelope.
	 */
	await manager.subscribe(query.topic, {
		codec: engine.framed,
		onUpdate: async (inner, wrapper) => {
			const note = await envelopes.receiving.unwrap(inner);
			renderUpdate(note, { inner, wrapper });
		},
		onGap: (_gapTopic, gap) => {
			gapReport.textContent = `gap: expected ${gap.expected}, received ${gap.received}`;
		},
		onEnd: () => {
			status.textContent = "completed";
		},
	});

	status.textContent = "subscribed";

	publishForm.addEventListener("submit", (event) => {
		event.preventDefault();
		void publish(manager, { topic: query.topic, text: payloadInput.value }, envelopes.publishing);
	});
}

main().catch((error: unknown) => {
	status.textContent = `error: ${String(error)}`;
});
