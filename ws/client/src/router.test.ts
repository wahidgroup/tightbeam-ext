import { describe, expect, it } from "vitest";

import type { Frame } from "./index.js";
import type { Note } from "./testing/notes.js";
import {
	Route,
	Router,
	TightbeamWsClient,
	UnroutedTopicError,
} from "./index.js";
import { NotePayload } from "./testing/notes.js";

/**
 * Frames built through the real builder route to the handler whose prefix
 * matches, decoded through the route's codec or envelope.
 */

const engine = await TightbeamWsClient.init();
const Notes = engine.wrapping(NotePayload);

const TEXT = new TextDecoder();
const SIGNING_KEY = engine.signingKey(new Uint8Array(32).fill(1));

/**
 * Notes that MUST carry a signature under {@link SIGNING_KEY}.
 */
const SignedNotes = engine.envelope(Notes).signed(SIGNING_KEY);

/**
 * A frame carrying `note` under `topic`, built through the real builder.
 */
async function noteFrame(topic: string, note: Note): Promise<Frame> {
	const built = await engine
		.frameBuilder()
		.withId(topic)
		.withOrder(1)
		.withMessage(Notes, note)
		.build();
	return built;
}

/**
 * A routing table that records which route served each message.
 */
function recordingTable(): {
	served: Record<string, Note[]>;
	routes: Router;
} {
	const served: Record<string, Note[]> = {
		"tick/": [],
		"tick/spot/": [],
		"chat/": [],
	};
	const recorder = (prefix: string): Route => {
		return Route.of(Notes, (note: Note) => {
			served[prefix]?.push(note);
			return undefined;
		});
	};

	const routes = new Router({
		"tick/": recorder("tick/"),
		"tick/spot/": recorder("tick/spot/"),
		"chat/": recorder("chat/"),
	});

	return { served, routes };
}

describe("Router", () => {
	const dispatches = [
		{ topic: "tick/AAPL", servedBy: "tick/" },
		{ topic: "tick/spot/BTC", servedBy: "tick/spot/" },
		{ topic: "chat/lobby", servedBy: "chat/" },
	] as const;

	it.each(dispatches)(
		"routes $topic to the $servedBy handler",
		async ({ topic, servedBy }) => {
			const { served, routes } = recordingTable();
			const note = { author: "ada", text: topic };

			const response = await routes.dispatch(
				await noteFrame(topic, note),
			);
			expect(response).toBeUndefined();
			expect(served[servedBy]).toEqual([note]);
		},
	);

	it("prefers the longest matching prefix regardless of table order", async () => {
		const { served, routes } = recordingTable();

		await routes.dispatch(
			await noteFrame("tick/spot/ETH", { author: "ada", text: "spot" }),
		);

		expect(served["tick/spot/"]).toEqual([{ author: "ada", text: "spot" }]);
		expect(served["tick/"]).toEqual([]);
	});

	it("relays the handler's response frame", async () => {
		const reply = await noteFrame("chat/lobby", {
			author: "ada",
			text: "pong",
		});
		const routes = new Router({
			"chat/": Route.of(Notes, () => reply),
		});

		const response = await routes.dispatch(
			await noteFrame("chat/lobby", { author: "ada", text: "ping" }),
		);
		expect(response?.message(Notes)).toEqual({
			author: "ada",
			text: "pong",
		});
	});

	it("hands the raw frame to the handler alongside the message", async () => {
		const topics: string[] = [];
		const routes = new Router({
			"chat/": Route.of(Notes, (note: Note, request: Frame) => {
				topics.push(`${TEXT.decode(request.id)}:${note.text}`);
				return undefined;
			}),
		});

		const note = { author: "ada", text: "hey" };
		const request = await noteFrame("chat/lobby", note);
		await routes.dispatch(request);

		expect(topics).toEqual(["chat/lobby:hey"]);
	});

	it("rejects an unrouted topic so the stream answers Unimplemented", async () => {
		const { routes } = recordingTable();
		const unrouted = routes.dispatch(
			await noteFrame("presence/lobby", { author: "ada", text: "?" }),
		);

		await expect(unrouted).rejects.toThrow(UnroutedTopicError);
		await expect(unrouted).rejects.toThrow("presence/lobby");
		await expect(unrouted).rejects.toMatchObject({
			code: "Unimplemented",
		});
	});
});

describe("Route.sealed", () => {
	it("hands the handler a message whose signature verified", async () => {
		const served: Note[] = [];
		const routes = new Router({
			"chat/": Route.sealed(SignedNotes, (note: Note) => {
				served.push(note);
				return undefined;
			}),
		});

		const signed = await SignedNotes.frame({
			author: "ada",
			text: "signed",
		})
			.withId("chat/lobby")
			.build();
		await routes.dispatch(signed);

		expect(served).toEqual([{ author: "ada", text: "signed" }]);
	});

	it("refuses an unsigned frame before the handler decodes it", async () => {
		const served: Note[] = [];
		const routes = new Router({
			"chat/": Route.sealed(SignedNotes, (note: Note) => {
				served.push(note);
				return undefined;
			}),
		});

		const unsigned = routes.dispatch(
			await noteFrame("chat/lobby", { author: "ada", text: "forged" }),
		);

		await expect(unsigned).rejects.toMatchObject({
			code: "ENVELOPE_UNSIGNED",
		});
		expect(served).toEqual([]);
	});
});
