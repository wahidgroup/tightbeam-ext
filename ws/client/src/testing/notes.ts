/**
 * The JSON note that the client unit tests round-trip.
 */

/**
 * A note: its author and its text.
 */
export interface Note {
	readonly author: string;
	readonly text: string;
}

/**
 * The JSON payload of a {@link Note}, for `Engine.wrapping`.
 */
export const NotePayload = {
	encode(note: Note): Uint8Array {
		const json = JSON.stringify(note);
		const payload = new TextEncoder().encode(json);
		return payload;
	},

	/**
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
