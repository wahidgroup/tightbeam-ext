import { describe, expect, expectTypeOf, it } from "vitest";

import type { Signatory } from "./crypto.js";
import type { Envelope } from "./envelope.js";
import type { Note } from "./testing/notes.js";
import { Engine } from "./index.js";
import { NotePayload } from "./testing/notes.js";
import { NobleSignatory } from "./testing/noble_signatory.js";

/**
 * The envelope's contract: every declared layer applies on `frame()` and
 * reverses on `unwrap()`, and a received frame missing a declared
 * signature or seal REJECTS instead of degrading.
 */

const engine = await Engine.load();
const Notes = engine.wrapping(NotePayload);

const SIGNING_KEY = engine.signingKey(new Uint8Array(32).fill(1));
const OTHER_KEY = engine.signingKey(new Uint8Array(32).fill(2));
const TOPIC_KEY = new Uint8Array(32).fill(7);
const TOPIC_KEY_ID = new TextEncoder().encode("tbws/test/topic/v1");
const TOPIC_CIPHER = engine.aes256Gcm({ key: TOPIC_KEY, keyId: TOPIC_KEY_ID });

/**
 * Both halves of the authenticity of {@link SIGNING_KEY}.
 */
const SIGNED = { signer: SIGNING_KEY, verifier: SIGNING_KEY.verifyingKey() };

/**
 * Both halves of the topic seal.
 */
const SEALED = { sealer: TOPIC_CIPHER, opener: TOPIC_CIPHER };

/**
 * Both halves of the profile compression.
 */
const COMPRESSED = { compressor: engine.zstd(), inflator: engine.zstd() };

const DECODER = new TextDecoder();

const NOTE: Note = { author: "ada", text: "hello" };

/**
 * A Signatory that signs with the profile key but is not an instanceof
 * Secp256k1SigningKey, standing in for a wallet that cannot verify.
 */
const WALLET: Signatory = {
	signerId: (): Uint8Array => SIGNING_KEY.signerId(),
	signPrehash: (prehash: Uint8Array): Promise<Uint8Array> => SIGNING_KEY.signPrehash(prehash),
};

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
		notes: engine.envelope(Notes).signed(SIGNED),
		signed: true,
		sealed: false,
		compressed: false,
	},
	{
		name: "sealed",
		notes: engine.envelope(Notes).sealed(SEALED),
		signed: false,
		sealed: true,
		compressed: false,
	},
	{
		name: "compressed",
		notes: engine.envelope(Notes).compressed(COMPRESSED),
		signed: false,
		sealed: false,
		compressed: true,
	},
	{
		name: "all layers",
		notes: engine.envelope(Notes).signed(SIGNED).sealed(SEALED).compressed(COMPRESSED),
		signed: true,
		sealed: true,
		compressed: true,
	},
];

describe("Envelope round-trips", () => {
	it.for(ROUND_TRIPS)(
		"$name: builds with the declared layers and unwraps",
		async ({ notes, signed, sealed, compressed }) => {
			const built = await notes.frame(NOTE).withId("frame").build();
			expect(built.signed).toBe(signed);
			expect(built.confidential).toBe(sealed);
			expect(built.compressed).toBe(compressed);

			await expect(notes.unwrap(built)).resolves.toEqual(NOTE);
		},
	);

	it("keeps the builder's metadata surface", async () => {
		const notes = engine.envelope(Notes).signed(SIGNED);
		const built = await notes.frame(NOTE).withId("note-1").withOrder(7).build();
		expect(DECODER.decode(built.id)).toBe("note-1");
		expect(built.order).toBe(7n);
	});
});

describe("Envelope one-sided parties", () => {
	it("a verify-only subscriber unwraps a peer's signed frame", async () => {
		const publisher = engine.envelope(Notes).signed(SIGNED);
		const subscriber = engine.envelope(Notes).signed({ verifier: SIGNING_KEY.verifyingKey() });

		const built = await publisher.frame(NOTE).withId("frame").build();
		await expect(subscriber.unwrap(built)).resolves.toEqual(NOTE);
	});

	it("HPKE halves compose one side each", async () => {
		const recipientSecret = new Uint8Array(32).fill(3);
		const recipientPublic = engine.signingKey(recipientSecret).verifyingKey().toSec1Bytes();

		const publisher = engine.envelope(Notes).sealed({ sealer: engine.hpkeEncryptor(recipientPublic) });
		const subscriber = engine.envelope(Notes).sealed({ opener: engine.hpkeDecryptor(recipientSecret) });

		const built = await publisher.frame(NOTE).withId("frame").build();
		await expect(subscriber.unwrap(built)).resolves.toEqual(NOTE);
	});

	it("a BYO signatory pairs with its own FrameVerifier", async () => {
		const byo = new NobleSignatory(engine, new Uint8Array(32).fill(5));
		const notes = engine.envelope(Notes).signed({ signer: byo, verifier: byo.verifier });

		const built = await notes.frame(NOTE).withId("frame").build();
		await expect(notes.unwrap(built)).resolves.toEqual(NOTE);
	});
});

describe("Envelope halves", () => {
	it("a write to the signature halves after the declaration leaves the envelope as declared", async () => {
		const halves = { ...SIGNED };
		const notes = engine.envelope(Notes).signed(halves);
		halves.signer = OTHER_KEY;

		const built = await notes.frame(NOTE).withId("frame").build();
		await expect(notes.unwrap(built)).resolves.toEqual(NOTE);
	});

	it("a write to the seal halves after the declaration leaves the envelope as declared", async () => {
		const halves = { ...SEALED };
		const notes = engine.envelope(Notes).sealed(halves);
		halves.sealer = engine.aes256Gcm({ key: new Uint8Array(32).fill(8), keyId: TOPIC_KEY_ID });

		const built = await notes.frame(NOTE).withId("frame").build();
		await expect(notes.unwrap(built)).resolves.toEqual(NOTE);
	});
});

describe("Envelope enforcement", () => {
	it("rejects an unsigned frame when authenticity is declared", async () => {
		const unsigned = await engine.envelope(Notes).frame(NOTE).withId("frame").build();
		const strict = engine.envelope(Notes).signed(SIGNED);
		await expect(strict.unwrap(unsigned)).rejects.toMatchObject({
			code: "EnvelopeUnsigned",
		});
	});

	it("rejects a frame signed by someone else", async () => {
		const forged = await engine.envelope(Notes).signed({ signer: OTHER_KEY }).frame(NOTE).withId("frame").build();

		const strict = engine.envelope(Notes).signed(SIGNED);
		await expect(strict.unwrap(forged)).rejects.toThrow(/signature verification/i);
	});

	it("rejects a cleartext frame when confidentiality is declared", async () => {
		const cleartext = await engine.envelope(Notes).frame(NOTE).withId("frame").build();
		const strict = engine.envelope(Notes).sealed(SEALED);
		await expect(strict.unwrap(cleartext)).rejects.toMatchObject({
			code: "EnvelopeCleartext",
		});
	});

	it("rejects a sealed frame when no opener is declared", async () => {
		const sealed = await engine.envelope(Notes).sealed(SEALED).frame(NOTE).withId("frame").build();

		const blind = engine.envelope(Notes);
		await expect(blind.unwrap(sealed)).rejects.toMatchObject({
			code: "OpaqueBody",
			layer: "opener",
		});
	});

	it("rejects a compressed frame when no inflator is declared", async () => {
		const compressed = await engine.envelope(Notes).compressed(COMPRESSED).frame(NOTE).withId("frame").build();

		const blind = engine.envelope(Notes);
		await expect(blind.unwrap(compressed)).rejects.toMatchObject({
			code: "OpaqueBody",
			layer: "inflator",
		});
	});

	it("accepts an uncompressed frame when compression is declared", async () => {
		const plain = await engine.envelope(Notes).frame(NOTE).withId("frame").build();

		const lenient = engine.envelope(Notes).compressed(COMPRESSED);
		await expect(lenient.unwrap(plain)).resolves.toEqual(NOTE);
	});
});

describe("Envelope directions", () => {
	const verifyOnly = engine.envelope(Notes).signed({ verifier: SIGNING_KEY.verifyingKey() });
	const openOnly = engine.envelope(Notes).sealed({ opener: engine.hpkeDecryptor(new Uint8Array(32).fill(3)) });
	const signOnly = engine.envelope(Notes).signed({ signer: WALLET });

	it("types a one-sided envelope by the directions it runs", () => {
		expectTypeOf(verifyOnly).toEqualTypeOf<Envelope<Note, false, true>>();
		expectTypeOf(openOnly).toEqualTypeOf<Envelope<Note, false, true>>();
		expectTypeOf(signOnly).toEqualTypeOf<Envelope<Note, true, false>>();
	});

	it.for([
		{ name: "verify-only", envelope: verifyOnly },
		{ name: "open-only", envelope: openOnly },
	])("a $name envelope refuses to build for an untyped caller", ({ envelope }) => {
		const framing = (): unknown => Reflect.apply(envelope.frame, envelope, [NOTE]);
		expect(framing).toThrow(expect.objectContaining({ code: "EnvelopeSender" }));
	});

	it("a sign-only envelope refuses to unwrap for an untyped caller", async () => {
		const built = await signOnly.frame(NOTE).withId("frame").build();
		const unwrapping: unknown = Reflect.apply(signOnly.unwrap, signOnly, [built]);
		await expect(unwrapping).rejects.toMatchObject({
			code: "EnvelopeReceiver",
		});
	});
});
