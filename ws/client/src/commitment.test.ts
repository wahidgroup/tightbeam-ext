import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";

import type { CommitmentSalt } from "#wasm";

import { TightbeamWsClient } from "./index.js";

/**
 * Detached message commitments: commit/verify must realize a
 * disclose-then-verify proof and reproduce the digests tightbeam-rs
 * `Opening` publishes.
 */

const engine = await TightbeamWsClient.init();

const TEXT = new TextEncoder();
const HASHER = engine.sha3_256;
const BODY = engine.opaque.encode(TEXT.encode("committed body"));
const OTHER_BODY = engine.opaque.encode(TEXT.encode("some other body"));
const SALT_OCTETS = TEXT.encode("blinding-salt-of-the-body");
const OTHER_SALT_OCTETS = TEXT.encode("some-other-blinding-salt");

/**
 * The shared payload and salt of the TypeScript/Rust opening interop
 * fixture, with the commitment Rust `Opening::prove::<Sha3_256>`.
 */
const INTEROP_BODY = engine.opaque.encode(
	TEXT.encode("tightbeam opening interop fixture body"),
);
const INTEROP_SALT_OCTETS = TEXT.encode("opening-interop-salt");
const INTEROP_COMMITMENT_HEX =
	"678bec1605c349a2af6ceaa627569d31d57759ee2fbeffd2ac33026df930e04e";

/**
 * The interop commitment digest as bytes, for direct comparison.
 */
const INTEROP_COMMITMENT_DIGEST = hexToBytes(INTEROP_COMMITMENT_HEX);

/**
 * A fresh salt over `octets`. An opening takes the salt it receives, so each
 * opening parses its own.
 */
function saltOf(octets: Uint8Array): CommitmentSalt {
	const salt = engine.salt(octets);
	return salt;
}

describe("Opening", () => {
	it.each([
		{
			name: "accepts the matching opening",
			openBody: BODY,
			openSalt: SALT_OCTETS,
			expected: true,
		},
		{
			name: "rejects an opening with the wrong salt",
			openBody: BODY,
			openSalt: OTHER_SALT_OCTETS,
			expected: false,
		},
		{
			name: "rejects an opening over another body",
			openBody: OTHER_BODY,
			openSalt: SALT_OCTETS,
			expected: false,
		},
	])("$name", async ({ openBody, openSalt, expected }) => {
		const proving = engine.opening(saltOf(SALT_OCTETS), BODY);
		const commitment = await proving.commit(HASHER);
		const disclosed = engine.opening(saltOf(openSalt), openBody);

		await expect(disclosed.verify(HASHER, commitment)).resolves.toBe(
			expected,
		);
	});

	it("publishes the commitment under the hasher's algorithm OID", async () => {
		const opening = engine.opening(saltOf(SALT_OCTETS), BODY);
		const commitment = await opening.commit(HASHER);

		const algorithm = commitment.algorithmOid.toString();
		expect(algorithm).toBe(engine.profile.sha3_256.toString());
		expect(opening.bodyDer).toEqual(BODY);
	});

	it("rejects a commitment carried under another algorithm OID", async () => {
		const opening = engine.opening(saltOf(SALT_OCTETS), BODY);
		const commitment = await opening.commit(HASHER);
		const relabeled = engine.digestInfo(
			engine.profile.zstd,
			commitment.digest,
		);

		await expect(opening.verify(HASHER, relabeled)).resolves.toBe(false);
	});

	it("hides the body: a salted commitment differs from the plain digest", async () => {
		const plainDigest = await HASHER.digest(BODY);
		const opening = engine.opening(saltOf(SALT_OCTETS), BODY);

		const commitment = await opening.commit(HASHER);
		expect(commitment.digest).not.toEqual(plainDigest);
	});

	it("digests the plain mode byte and the body under an empty salt", async () => {
		const plainPreimage = new Uint8Array(BODY.length + 1);
		plainPreimage.set(BODY, 1);

		const plainDigest = await HASHER.digest(plainPreimage);
		const opening = engine.opening(saltOf(new Uint8Array()), BODY);
		const commitment = await opening.commit(HASHER);
		expect(commitment.digest).toEqual(plainDigest);
	});

	it("keeps the salt it parsed when the caller writes to the buffer", async () => {
		const buffer = new Uint8Array(SALT_OCTETS);
		const salt = engine.salt(buffer);
		buffer.fill(0);

		const opening = engine.opening(salt, BODY);
		const reference = engine.opening(saltOf(SALT_OCTETS), BODY);
		const commitment = await reference.commit(HASHER);
		await expect(opening.verify(HASHER, commitment)).resolves.toBe(true);
	});

	it("keeps the committed body when the caller writes to the buffer", async () => {
		const buffer = new Uint8Array(BODY);
		const opening = engine.opening(saltOf(SALT_OCTETS), buffer);
		const commitment = await opening.commit(HASHER);
		buffer.fill(0);

		await expect(opening.verify(HASHER, commitment)).resolves.toBe(true);
	});

	it("takes the salt it receives, so a second opening over it refuses", () => {
		const salt = saltOf(SALT_OCTETS);
		engine.opening(salt, BODY);

		expect(() => engine.opening(salt, BODY)).toThrow(
			expect.objectContaining({ code: "CommitmentSpent" }),
		);
	});

	it("a disposed opening refuses a later call with OpeningReleased", async () => {
		const opening = engine.opening(saltOf(SALT_OCTETS), BODY);
		opening[Symbol.dispose]();
		opening[Symbol.dispose]();

		await expect(opening.commit(HASHER)).rejects.toMatchObject({
			code: "OpeningReleased",
		});
	});

	it("refuses a salt too short to hide the body", () => {
		const shortSalt = new Uint8Array(15);
		expect(() => engine.salt(shortSalt)).toThrow(
			expect.objectContaining({ code: "InvalidSaltLength" }),
		);
	});

	it("reproduces the commitment tightbeam-rs publishes over the shared fixture", async () => {
		const opening = engine.opening(
			saltOf(INTEROP_SALT_OCTETS),
			INTEROP_BODY,
		);
		const commitment = await opening.commit(HASHER);
		expect(commitment.digest).toEqual(INTEROP_COMMITMENT_DIGEST);
	});

	it("verifies a commitment disclosed by a tightbeam-rs prover", async () => {
		const commitment = engine.digestInfo(
			engine.profile.sha3_256,
			INTEROP_COMMITMENT_DIGEST,
		);
		const disclosed = engine.opening(
			saltOf(INTEROP_SALT_OCTETS),
			INTEROP_BODY,
		);
		await expect(disclosed.verify(HASHER, commitment)).resolves.toBe(true);
	});
});
