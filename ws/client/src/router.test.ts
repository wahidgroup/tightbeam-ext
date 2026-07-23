import { describe, expect, it } from "vitest";

import type { Frame, MessageCodec } from "./index.js";
import { UnroutedTopicError, frame, route, router, wrapped } from "./index.js";

/**
 * Frames built through the real builder route to the handler whose prefix
 * matches, decoded through the route's codec.
 */

const TEXT = new TextDecoder();

/**
 * A one-field JSON message, enough to prove typed decode through a route.
 */
interface Note {
	readonly text: string;
}

const NoteCodec: MessageCodec<Note> = wrapped({
	encode(message: Note): Uint8Array {
		const payload = new TextEncoder().encode(JSON.stringify(message));
		return payload;
	},
	decode(payload: Uint8Array): Note {
		const parsed: unknown = JSON.parse(TEXT.decode(payload));
		if (
			typeof parsed !== "object" ||
			parsed === null ||
			!("text" in parsed) ||
			typeof parsed.text !== "string"
		) {
			throw new Error("not a note");
		}

		const note = { text: parsed.text };
		return note;
	},
});

/**
 * A frame carrying `note` under `topic`, built through the real builder.
 */
async function noteFrame(topic: string, note: Note): Promise<Frame> {
	const built = await frame()
		.withId(topic)
		.withOrder(1)
		.withMessage(NoteCodec, note)
		.build();
	return built;
}

/**
 * A routing table that records which route served each message.
 */
function recordingTable(): {
	served: Record<string, Note[]>;
	handler: (frame: Frame) => Promise<Frame | undefined>;
} {
	const served: Record<string, Note[]> = {
		"tick/": [],
		"tick/spot/": [],
		"chat/": [],
	};
	const recorder = (prefix: string) => {
		return route(NoteCodec, (note: Note) => {
			served[prefix]?.push(note);
			return undefined;
		});
	};

	const handler = router({
		"tick/": recorder("tick/"),
		"tick/spot/": recorder("tick/spot/"),
		"chat/": recorder("chat/"),
	});

	return { served, handler };
}

describe("router", () => {
	const dispatches = [
		{ topic: "tick/AAPL", servedBy: "tick/" },
		{ topic: "tick/spot/BTC", servedBy: "tick/spot/" },
		{ topic: "chat/lobby", servedBy: "chat/" },
	] as const;

	it.each(dispatches)(
		"routes $topic to the $servedBy handler",
		async ({ topic, servedBy }) => {
			const { served, handler } = recordingTable();
			const note = { text: topic };

			const response = await handler(await noteFrame(topic, note));
			expect(response).toBeUndefined();
			expect(served[servedBy]).toEqual([note]);
		},
	);

	it("prefers the longest matching prefix regardless of table order", async () => {
		const { served, handler } = recordingTable();

		await handler(await noteFrame("tick/spot/ETH", { text: "spot" }));

		expect(served["tick/spot/"]).toEqual([{ text: "spot" }]);
		expect(served["tick/"]).toEqual([]);
	});

	it("relays the handler's response frame", async () => {
		const reply = await noteFrame("chat/lobby", { text: "pong" });
		const handler = router({
			"chat/": route(NoteCodec, () => reply),
		});

		const response = await handler(
			await noteFrame("chat/lobby", { text: "ping" }),
		);

		expect(response?.message(NoteCodec)).toEqual({ text: "pong" });
	});

	it("hands the raw frame to the handler alongside the message", async () => {
		const topics: string[] = [];
		const handler = router({
			"chat/": route(NoteCodec, (note: Note, request: Frame) => {
				topics.push(`${TEXT.decode(request.id)}:${note.text}`);
				return undefined;
			}),
		});

		await handler(await noteFrame("chat/lobby", { text: "hey" }));

		expect(topics).toEqual(["chat/lobby:hey"]);
	});

	it("rejects an unrouted topic so the stream answers Unimplemented", async () => {
		const { handler } = recordingTable();

		const unrouted = handler(
			await noteFrame("presence/lobby", { text: "?" }),
		);

		await expect(unrouted).rejects.toThrow(UnroutedTopicError);
		await expect(unrouted).rejects.toThrow("presence/lobby");
		await expect(unrouted).rejects.toMatchObject({
			code: "Unimplemented",
		});
	});
});
