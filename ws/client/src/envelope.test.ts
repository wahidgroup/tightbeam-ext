import { describe, expect, it } from "vitest";

import type { FrameVerifier, Signatory } from "./crypto.js";
import type { Envelope } from "./envelope.js";
import type { Note } from "./testing/notes.js";
import { TightbeamWsClient, ValidationError } from "./index.js";
import { NotePayload } from "./testing/notes.js";
import { NobleSignatory } from "./testing/noble_signatory.js";

/**
 * The envelope's contract: every declared layer applies on `frame()` and
 * reverses on `unwrap()`, and a received frame missing a declared
 * signature or seal REJECTS instead of degrading.
 */

const engine = await TightbeamWsClient.init();
const Notes = engine.wrapping(NotePayload);

const SIGNING_KEY = engine.signingKey(new Uint8Array(32).fill(1));
const OTHER_KEY = engine.signingKey(new Uint8Array(32).fill(2));
const TOPIC_KEY = new Uint8Array(32).fill(7);
const TOPIC_KEY_ID = new TextEncoder().encode("tbws/test/topic/v1");

const DECODER = new TextDecoder();

const NOTE: Note = { author: "ada", text: "hello" };

/**
 * A Signatory that signs with the profile key but is not an instanceof
 * Secp256k1SigningKey. Optionally exposes a verify half via `verifier`.
 */
function profileBackedSignatory(options: {
	readonly verifier?: FrameVerifier;
}): Signatory {
	const base = {
		signerId: (): Uint8Array => SIGNING_KEY.signerId(),
		signPrehash: (prehash: Uint8Array): Promise<Uint8Array> =>
			SIGNING_KEY.signPrehash(prehash),
	};

	if (options.verifier === undefined) {
		return base;
	}

	return { ...base, verifier: options.verifier };
}

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
		notes: engine.envelope(Notes),
		signed: false,
		sealed: false,
		compressed: false,
	},
	{
		name: "signed",
		notes: engine.envelope(Notes).signed(SIGNING_KEY),
		signed: true,
		sealed: false,
		compressed: false,
	},
	{
		name: "sealed",
		notes: engine
			.envelope(Notes)
			.sealed(engine.aes256Gcm({ key: TOPIC_KEY, keyId: TOPIC_KEY_ID })),
		signed: false,
		sealed: true,
		compressed: false,
	},
	{
		name: "compressed",
		notes: engine.envelope(Notes).compressed(engine.zstd()),
		signed: false,
		sealed: false,
		compressed: true,
	},
	{
		name: "all layers",
		notes: engine
			.envelope(Notes)
			.signed(SIGNING_KEY)
			.sealed(engine.aes256Gcm({ key: TOPIC_KEY, keyId: TOPIC_KEY_ID }))
			.compressed(engine.zstd()),
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
		const notes = engine.envelope(Notes).signed(SIGNING_KEY);
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
			const publisher = engine.envelope(Notes).signed(SIGNING_KEY);
			const subscriber = engine.envelope(Notes).verified(verifier());

			const built = await publisher.frame(NOTE).build();
			await expect(subscriber.unwrap(built)).resolves.toEqual(NOTE);
		},
	);

	it("HPKE halves compose one side each", async () => {
		const recipientSecret = new Uint8Array(32).fill(3);
		const recipientPublic = engine
			.signingKey(recipientSecret)
			.verifyingKey()
			.toSec1Bytes();

		const publisher = engine
			.envelope(Notes)
			.sealed(engine.hpkeEncryptor(recipientPublic));
		const subscriber = engine
			.envelope(Notes)
			.sealed(engine.hpkeDecryptor(recipientSecret));

		const built = await publisher.frame(NOTE).build();
		await expect(subscriber.unwrap(built)).resolves.toEqual(NOTE);
	});
});

describe("Envelope Signatory.verifier", () => {
	it("unwraps when an external signatory exposes a verifier", async () => {
		const external = engine
			.envelope(Notes)
			.signed(profileBackedSignatory({ verifier: SIGNING_KEY.verifier }));

		const built = await external.frame(NOTE).build();
		await expect(external.unwrap(built)).resolves.toEqual(NOTE);
	});

	it("unwraps when a BYO signatory carries its own FrameVerifier", async () => {
		const byo = new NobleSignatory(engine, new Uint8Array(32).fill(5));
		const notes = engine.envelope(Notes).signed(byo);

		const built = await notes.frame(NOTE).build();
		await expect(notes.unwrap(built)).resolves.toEqual(NOTE);
	});

	it("verified(BYO FrameVerifier) unwraps a BYO-signed frame", async () => {
		const byo = new NobleSignatory(engine, new Uint8Array(32).fill(5));
		const publisher = engine.envelope(Notes).signed(byo);
		const subscriber = engine.envelope(Notes).verified(byo.verifier);

		const built = await publisher.frame(NOTE).build();
		await expect(subscriber.unwrap(built)).resolves.toEqual(NOTE);
	});
});

describe("Envelope enforcement", () => {
	it("rejects an unsigned frame when authenticity is declared", async () => {
		const unsigned = await engine.envelope(Notes).frame(NOTE).build();
		const strict = engine.envelope(Notes).signed(SIGNING_KEY);
		await expect(strict.unwrap(unsigned)).rejects.toMatchObject({
			code: "ENVELOPE_UNSIGNED",
		});
	});

	it("rejects a frame signed by someone else", async () => {
		const forged = await engine
			.envelope(Notes)
			.signed(OTHER_KEY)
			.frame(NOTE)
			.build();

		const strict = engine.envelope(Notes).signed(SIGNING_KEY);
		await expect(strict.unwrap(forged)).rejects.toThrow(
			/signature verification/i,
		);
	});

	it("rejects a cleartext frame when confidentiality is declared", async () => {
		const cleartext = await engine.envelope(Notes).frame(NOTE).build();
		const strict = engine
			.envelope(Notes)
			.sealed(engine.aes256Gcm({ key: TOPIC_KEY, keyId: TOPIC_KEY_ID }));
		await expect(strict.unwrap(cleartext)).rejects.toMatchObject({
			code: "ENVELOPE_CLEARTEXT",
		});
	});

	it("rejects a sealed frame when no opener is declared", async () => {
		const sealed = await engine
			.envelope(Notes)
			.sealed(engine.aes256Gcm({ key: TOPIC_KEY, keyId: TOPIC_KEY_ID }))
			.frame(NOTE)
			.build();

		const blind = engine.envelope(Notes);
		await expect(blind.unwrap(sealed)).rejects.toMatchObject({
			code: "MISSING_OPENER",
		});
	});

	it("rejects a compressed frame when no inflator is declared", async () => {
		const compressed = await engine
			.envelope(Notes)
			.compressed(engine.zstd())
			.frame(NOTE)
			.build();

		const blind = engine.envelope(Notes);
		await expect(blind.unwrap(compressed)).rejects.toMatchObject({
			code: "MISSING_INFLATOR",
		});
	});

	it("accepts an uncompressed frame when compression is declared", async () => {
		const plain = await engine.envelope(Notes).frame(NOTE).build();

		const lenient = engine.envelope(Notes).compressed(engine.zstd());
		await expect(lenient.unwrap(plain)).resolves.toEqual(NOTE);
	});
});

describe("Envelope wrap-side strictness", () => {
	it("a verify-only envelope refuses to build", () => {
		const verifier = SIGNING_KEY.verifyingKey();
		const readOnly = engine.envelope(Notes).verified(verifier);
		expect(() => readOnly.frame(NOTE)).toThrow(ValidationError);
		expect(() => readOnly.frame(NOTE)).toThrow(
			expect.objectContaining({ code: "ENVELOPE_SIGNER" }),
		);
	});

	it("an open-only envelope refuses to build", () => {
		const recipientSecret = new Uint8Array(32).fill(3);
		const readOnly = engine
			.envelope(Notes)
			.sealed(engine.hpkeDecryptor(recipientSecret));

		expect(() => readOnly.frame(NOTE)).toThrow(ValidationError);
		expect(() => readOnly.frame(NOTE)).toThrow(
			expect.objectContaining({ code: "ENVELOPE_SEALER" }),
		);
	});

	it("an external signatory without a verifier refuses to unwrap", async () => {
		const signatory = profileBackedSignatory({});
		const external = engine.envelope(Notes).signed(signatory);
		const built = await external.frame(NOTE).build();
		await expect(external.unwrap(built)).rejects.toMatchObject({
			code: "ENVELOPE_VERIFIER",
		});
	});
});
