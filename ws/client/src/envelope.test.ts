import { describe, expect, it } from "vitest";

import type { Envelope } from "./envelope.js";
import type { FrameVerifier, Signatory } from "./crypto.js";
import type { MessageCodec } from "./message.js";
import { Aes256Gcm, Secp256k1SigningKey } from "./crypto.js";
import { ZstdCompression } from "./compress.js";
import {
	HpkeDecryptor,
	HpkeEncryptor,
	ValidationError,
	envelope,
	initClient,
	wrapped,
} from "./index.js";
import { NobleSignatory } from "./testing/noble_signatory.js";

/**
 * The envelope's contract: every declared layer applies on `frame()` and
 * reverses on `unwrap()`, and a received frame missing a declared
 * signature or seal REJECTS instead of degrading.
 */

const SIGNING_KEY = Secp256k1SigningKey.fromBytes(new Uint8Array(32).fill(1));
const OTHER_KEY = Secp256k1SigningKey.fromBytes(new Uint8Array(32).fill(2));
const TOPIC_KEY = new Uint8Array(32).fill(7);
const TOPIC_KEY_ID = new TextEncoder().encode("tbws/test/topic/v1");

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

interface Note {
	text: string;
}

const Notes: MessageCodec<Note> = wrapped({
	encode(note: Note): Uint8Array {
		return ENCODER.encode(JSON.stringify(note));
	},
	decode(payload: Uint8Array): Note {
		const parsed: unknown = JSON.parse(DECODER.decode(payload));
		if (
			typeof parsed !== "object" ||
			parsed === null ||
			!("text" in parsed) ||
			typeof parsed.text !== "string"
		) {
			throw new Error("a note needs a string text");
		}

		return { text: parsed.text };
	},
});

const NOTE: Note = { text: "hello" };

/**
 * A Signatory that signs with the profile key but is not an instanceof
 * Secp256k1SigningKey. Optionally exposes a verify half via `verifier`.
 */
function profileBackedSignatory(options: {
	readonly verifier?: FrameVerifier;
}): Signatory {
	const base = {
		signatureAlgorithmOid: SIGNING_KEY.signatureAlgorithmOid,
		digestAlgorithmOid: SIGNING_KEY.digestAlgorithmOid,
		signerId: (): Uint8Array => SIGNING_KEY.signerId(),
		signPrehash: (prehash: Uint8Array): Promise<Uint8Array> =>
			SIGNING_KEY.signPrehash(prehash),
	};

	if (options.verifier === undefined) {
		return base;
	}

	return { ...base, verifier: options.verifier };
}

await initClient();

/**
 * One round-trip case: the composed envelope and the artifacts every
 * frame it builds must carry.
 */
interface RoundTrip {
	readonly name: string;
	readonly notes: Envelope<Note>;
	readonly signed: boolean;
	readonly sealed: boolean;
	readonly compressed: boolean;
}

const ROUND_TRIPS: RoundTrip[] = [
	{
		name: "codec only",
		notes: envelope(Notes),
		signed: false,
		sealed: false,
		compressed: false,
	},
	{
		name: "signed",
		notes: envelope(Notes).signed(SIGNING_KEY),
		signed: true,
		sealed: false,
		compressed: false,
	},
	{
		name: "sealed",
		notes: envelope(Notes).sealed(
			Aes256Gcm.fromKey(TOPIC_KEY, TOPIC_KEY_ID),
		),
		signed: false,
		sealed: true,
		compressed: false,
	},
	{
		name: "compressed",
		notes: envelope(Notes).compressed(new ZstdCompression()),
		signed: false,
		sealed: false,
		compressed: true,
	},
	{
		name: "all layers",
		notes: envelope(Notes)
			.signed(SIGNING_KEY)
			.sealed(Aes256Gcm.fromKey(TOPIC_KEY, TOPIC_KEY_ID))
			.compressed(new ZstdCompression()),
		signed: true,
		sealed: true,
		compressed: true,
	},
];

describe("Envelope round-trips", () => {
	it.for(ROUND_TRIPS)(
		"$name: builds with the declared layers and unwraps",
		async ({ notes, signed, sealed, compressed }) => {
			const built = await notes.frame(NOTE).build();
			expect(built.signed).toBe(signed);
			expect(built.confidential).toBe(sealed);
			expect(built.compressed).toBe(compressed);

			await expect(notes.unwrap(built)).resolves.toEqual(NOTE);
		},
	);

	it("keeps the builder's metadata surface", async () => {
		const notes = envelope(Notes).signed(SIGNING_KEY);
		const built = await notes
			.frame(NOTE)
			.withId("note-1")
			.withOrder(7)
			.build();
		expect(DECODER.decode(built.id)).toBe("note-1");
		expect(built.order).toBe(7n);
	});
});

describe("Envelope one-sided parties", () => {
	it.for([
		{
			name: "verifyingKey()",
			verifier: (): FrameVerifier => SIGNING_KEY.verifyingKey(),
		},
		{
			name: "signer.verifier",
			verifier: (): FrameVerifier => SIGNING_KEY.verifier,
		},
	])(
		"verified-only ($name) unwraps a peer's signed frame",
		async ({ verifier }) => {
			const publisher = envelope(Notes).signed(SIGNING_KEY);
			const subscriber = envelope(Notes).verified(verifier());

			const built = await publisher.frame(NOTE).build();
			await expect(subscriber.unwrap(built)).resolves.toEqual(NOTE);
		},
	);

	it("HPKE halves compose one side each", async () => {
		const recipientSecret = new Uint8Array(32).fill(3);
		const recipientPublic = Secp256k1SigningKey.fromBytes(recipientSecret)
			.verifyingKey()
			.toSec1Bytes();

		const publisher = envelope(Notes).sealed(
			HpkeEncryptor.fromBytes(recipientPublic),
		);
		const subscriber = envelope(Notes).sealed(
			HpkeDecryptor.fromBytes(recipientSecret),
		);

		const built = await publisher.frame(NOTE).build();
		await expect(subscriber.unwrap(built)).resolves.toEqual(NOTE);
	});
});

describe("Envelope Signatory.verifier", () => {
	it("unwraps when an external signatory exposes a verifier", async () => {
		const external = envelope(Notes).signed(
			profileBackedSignatory({ verifier: SIGNING_KEY.verifier }),
		);

		const built = await external.frame(NOTE).build();
		await expect(external.unwrap(built)).resolves.toEqual(NOTE);
	});

	it("unwraps when a BYO signatory carries its own FrameVerifier", async () => {
		const byo = new NobleSignatory(new Uint8Array(32).fill(5));
		const notes = envelope(Notes).signed(byo);

		const built = await notes.frame(NOTE).build();
		await expect(notes.unwrap(built)).resolves.toEqual(NOTE);
	});

	it("verified(BYO FrameVerifier) unwraps a BYO-signed frame", async () => {
		const byo = new NobleSignatory(new Uint8Array(32).fill(5));
		const publisher = envelope(Notes).signed(byo);
		const subscriber = envelope(Notes).verified(byo.verifier);

		const built = await publisher.frame(NOTE).build();
		await expect(subscriber.unwrap(built)).resolves.toEqual(NOTE);
	});
});

describe("Envelope enforcement", () => {
	it("rejects an unsigned frame when authenticity is declared", async () => {
		const unsigned = await envelope(Notes).frame(NOTE).build();
		const strict = envelope(Notes).signed(SIGNING_KEY);
		await expect(strict.unwrap(unsigned)).rejects.toMatchObject({
			code: "ENVELOPE_UNSIGNED",
		});
	});

	it("rejects a frame signed by someone else", async () => {
		const forged = await envelope(Notes)
			.signed(OTHER_KEY)
			.frame(NOTE)
			.build();

		const strict = envelope(Notes).signed(SIGNING_KEY);
		await expect(strict.unwrap(forged)).rejects.toThrow(
			/signature verification/i,
		);
	});

	it("rejects a cleartext frame when confidentiality is declared", async () => {
		const cleartext = await envelope(Notes).frame(NOTE).build();
		const strict = envelope(Notes).sealed(
			Aes256Gcm.fromKey(TOPIC_KEY, TOPIC_KEY_ID),
		);
		await expect(strict.unwrap(cleartext)).rejects.toMatchObject({
			code: "ENVELOPE_CLEARTEXT",
		});
	});

	it("rejects a sealed frame when no opener is declared", async () => {
		const sealed = await envelope(Notes)
			.sealed(Aes256Gcm.fromKey(TOPIC_KEY, TOPIC_KEY_ID))
			.frame(NOTE)
			.build();

		const blind = envelope(Notes);
		await expect(blind.unwrap(sealed)).rejects.toMatchObject({
			code: "ENVELOPE_OPENER",
		});
	});

	it("rejects a compressed frame when no inflator is declared", async () => {
		const compressed = await envelope(Notes)
			.compressed(new ZstdCompression())
			.frame(NOTE)
			.build();

		const blind = envelope(Notes);
		await expect(blind.unwrap(compressed)).rejects.toMatchObject({
			code: "ENVELOPE_INFLATOR",
		});
	});

	it("accepts an uncompressed frame when compression is declared", async () => {
		const plain = await envelope(Notes).frame(NOTE).build();

		const lenient = envelope(Notes).compressed(new ZstdCompression());
		await expect(lenient.unwrap(plain)).resolves.toEqual(NOTE);
	});
});

describe("Envelope wrap-side strictness", () => {
	it("a verify-only envelope refuses to build", () => {
		const readOnly = envelope(Notes).verified(SIGNING_KEY.verifyingKey());
		expect(() => readOnly.frame(NOTE)).toThrow(ValidationError);
		expect(() => readOnly.frame(NOTE)).toThrow(
			expect.objectContaining({ code: "ENVELOPE_SIGNER" }),
		);
	});

	it("an open-only envelope refuses to build", () => {
		const recipientSecret = new Uint8Array(32).fill(3);
		const readOnly = envelope(Notes).sealed(
			HpkeDecryptor.fromBytes(recipientSecret),
		);

		expect(() => readOnly.frame(NOTE)).toThrow(ValidationError);
		expect(() => readOnly.frame(NOTE)).toThrow(
			expect.objectContaining({ code: "ENVELOPE_SEALER" }),
		);
	});

	it("an external signatory without a verifier refuses to unwrap", async () => {
		const external = envelope(Notes).signed(profileBackedSignatory({}));
		const built = await external.frame(NOTE).build();
		await expect(external.unwrap(built)).rejects.toMatchObject({
			code: "ENVELOPE_VERIFIER",
		});
	});
});
