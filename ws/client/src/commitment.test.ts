import { describe, expect, it } from "vitest";

import { bodyPreimage } from "#wasm";

import { Opening } from "./commitment.js";
import { PROFILE_OIDS, Sha3_256 } from "./crypto.js";
import { initClient } from "./index.js";

/**
 * Detached message commitments: prove/verify must realize a
 * disclose-then-verify proof and reproduce the digests tightbeam-rs
 * `Opening` publishes.
 */

await initClient();

const TEXT = new TextEncoder();

const HASHER = new Sha3_256();

const BODY = bodyPreimage(TEXT.encode("committed body"));
const OTHER_BODY = bodyPreimage(TEXT.encode("some other body"));
const SALT = TEXT.encode("blinding-salt");
const OTHER_SALT = TEXT.encode("some-other-salt");
const EMPTY_SALT = new Uint8Array();

/**
 * The shared payload and salt of the TypeScript/Rust opening interop
 * fixture, with the commitment Rust `Opening::prove::<Sha3_256>`.
 */
const INTEROP_BODY = bodyPreimage(
	TEXT.encode("tightbeam opening interop fixture body"),
);
const INTEROP_SALT = TEXT.encode("opening-interop-salt");
const INTEROP_COMMITMENT_HEX =
	"60b6ac6b45c68572acafa88fa74257e84fc9dc71397a1a99265ecb454bf5e639";

function bytesFromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let index = 0; index < bytes.length; index += 1) {
		const pair = hex.slice(index * 2, index * 2 + 2);
		bytes[index] = Number.parseInt(pair, 16);
	}

	return bytes;
}

/**
 * The interop commitment digest as bytes, for direct comparison.
 */
const INTEROP_COMMITMENT_DIGEST = bytesFromHex(INTEROP_COMMITMENT_HEX);

describe("Opening", () => {
	it.each([
		{
			name: "accepts the matching opening",
			openBody: BODY,
			openSalt: SALT,
			expected: true,
		},
		{
			name: "rejects an opening with the wrong salt",
			openBody: BODY,
			openSalt: OTHER_SALT,
			expected: false,
		},
		{
			name: "rejects an opening over another body",
			openBody: OTHER_BODY,
			openSalt: SALT,
			expected: false,
		},
	])("$name", async ({ openBody, openSalt, expected }) => {
		const { commitment } = await Opening.prove(HASHER, BODY, SALT);
		const disclosed = Opening.fromParts(openSalt, openBody);

		await expect(disclosed.verify(HASHER, commitment)).resolves.toBe(
			expected,
		);
	});

	it("publishes the commitment under the hasher's algorithm OID", async () => {
		const { commitment, opening } = await Opening.prove(HASHER, BODY, SALT);
		expect(commitment.algorithmOid).toBe(PROFILE_OIDS.sha3_256);
		expect(opening.salt).toEqual(SALT);
		expect(opening.bodyDer).toEqual(BODY);
	});

	it("rejects a commitment carried under another algorithm OID", async () => {
		const { commitment, opening } = await Opening.prove(HASHER, BODY, SALT);
		const relabeled = { ...commitment, algorithmOid: PROFILE_OIDS.zstd };
		await expect(opening.verify(HASHER, relabeled)).resolves.toBe(false);
	});

	it("hides the body: a salted commitment differs from the plain digest", async () => {
		const plainDigest = await HASHER.digest(BODY);
		const { commitment } = await Opening.prove(HASHER, BODY, SALT);
		expect(commitment.digest).not.toEqual(plainDigest);
	});

	it("reproduces the plain body digest under an empty salt", async () => {
		const plainDigest = await HASHER.digest(BODY);
		const { commitment } = await Opening.prove(HASHER, BODY, EMPTY_SALT);
		expect(commitment.digest).toEqual(plainDigest);
	});

	it("reproduces the commitment tightbeam-rs publishes over the shared fixture", async () => {
		const { commitment } = await Opening.prove(
			HASHER,
			INTEROP_BODY,
			INTEROP_SALT,
		);
		expect(commitment.digest).toEqual(INTEROP_COMMITMENT_DIGEST);
	});

	it("verifies a commitment disclosed by a tightbeam-rs prover", async () => {
		const commitment = {
			algorithmOid: PROFILE_OIDS.sha3_256,
			digest: INTEROP_COMMITMENT_DIGEST,
		};

		const disclosed = Opening.fromParts(INTEROP_SALT, INTEROP_BODY);
		await expect(disclosed.verify(HASHER, commitment)).resolves.toBe(true);
	});
});
