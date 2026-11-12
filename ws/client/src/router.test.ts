import { describe, expect, it } from "vitest";

import type { Frame } from "./index.js";
import type { Note } from "./testing/notes.js";
import { Engine, Route, Router, UnroutedTopicError } from "./index.js";
import { NotePayload } from "./testing/notes.js";

/**
 * Frames built through the real builder route to the handler whose prefix
 * matches, decoded through the route's codec or envelope.
 */

const engine = await Engine.load();
const Notes = engine.wrapping(NotePayload);

const TEXT = new TextDecoder();
const SIGNING_KEY = engine.signingKey(new Uint8Array(32).fill(1));

/**
 * Notes that MUST carry a signature under {@link SIGNING_KEY}.
 */
const SignedNotes = engine.envelope(Notes).signed({ signer: SIGNING_KEY, verifier: SIGNING_KEY.verifyingKey() });

/**
 * A frame carrying `note` under `topic`, built through the real builder.
 */
async function noteFrame(topic: string, note: Note): Promise<Frame> {
	const built = await engine.messageBuilder(Notes, note).withId(topic).withOrder(1).build();
	return built;
}

/**
 * A route that answers each message with a note that names `prefix`, the
 * prefix it serves, and carries the text of the message.
 */
function answering(prefix: string): Route {
	const route = Route.of(Notes, (note: Note, request: Frame) => {
		const answer = { author: prefix, text: `${TEXT.decode(request.id)}:${note.text}` };
		return noteFrame(prefix, answer);
	});
	return route;
}

/**
 * A routing table whose routes each answer with the note of {@link answering}.
 */
const ROUTES = new Router({
	"tick/": answering("tick/"),
	"tick/spot/": answering("tick/spot/"),
	"chat/": answering("chat/"),
});

describe("Router", () => {
	const dispatches = [
		{ topic: "tick/AAPL", servedBy: "tick/" },
		{ topic: "tick/spot/BTC", servedBy: "tick/spot/" },
		{ topic: "tick/spot/ETH", servedBy: "tick/spot/" },
		{ topic: "chat/lobby", servedBy: "chat/" },
	] as const;

	it.each(dispatches)("answers $topic through the longest prefix, $servedBy", async ({ topic, servedBy }) => {
		const response = await ROUTES.dispatch(await noteFrame(topic, { author: "ada", text: "hi" }));

		await expect(response?.open(Notes)).resolves.toEqual({ author: servedBy, text: `${topic}:hi` });
	});

	it("answers no frame for a handler that answers none", async () => {
		const routes = new Router({ "chat/": Route.of(Notes, () => undefined) });

		const response = await routes.dispatch(await noteFrame("chat/lobby", { author: "ada", text: "hey" }));
		expect(response).toBeUndefined();
	});

	it("rejects an unrouted topic so the stream answers Unimplemented", async () => {
		const unrouted = ROUTES.dispatch(await noteFrame("presence/lobby", { author: "ada", text: "?" }));

		await expect(unrouted).rejects.toThrow(UnroutedTopicError);
		await expect(unrouted).rejects.toThrow("presence/lobby");
		await expect(unrouted).rejects.toMatchObject({
			code: "Unimplemented",
		});
	});
});

describe("Route.sealed", () => {
	const routes = new Router({
		"chat/": Route.sealed(SignedNotes, (note: Note) => noteFrame("chat/", { author: "chat/", text: note.text })),
	});

	it("answers a message whose signature verified", async () => {
		const signed = await SignedNotes.frame({ author: "ada", text: "signed" }).withId("chat/lobby").build();

		const response = await routes.dispatch(signed);
		await expect(response?.open(Notes)).resolves.toEqual({ author: "chat/", text: "signed" });
	});

	it("refuses an unsigned frame before the handler decodes it", async () => {
		const unsigned = routes.dispatch(await noteFrame("chat/lobby", { author: "ada", text: "forged" }));

		await expect(unsigned).rejects.toMatchObject({
			code: "EnvelopeUnsigned",
		});
	});
});
