import { describe, expect, it } from "vitest";

import { PROFILE_OIDS } from "./crypto.js";
import { ZstdCompression } from "./compress.js";
import { Opaque, ValidationError, frame, initClient } from "./index.js";

/**
 * The profile zstd compression: seekable-format streams that must
 * interoperate with tightbeam-rs `ZstdCompression` (zeekstd).
 */

await initClient();

const BODY = new Uint8Array([1, 2, 3, 4]);

/**
 * The shared payload of the TypeScript/Rust zstd interop fixtures.
 */
const INTEROP_PAYLOAD = new TextEncoder().encode(
	"tightbeam zstd interop fixture body ".repeat(8),
);

/**
 * A body compressed by Rust `ZstdCompression` (zeekstd) over
 * {@link INTEROP_PAYLOAD}: the profile inflator must open the stream a
 * tightbeam peer sends.
 */
const ZEEKSTD_FIXTURE_HEX =
	"28b52ffd00586d0100440274696768746265616d207a73746420696e7465726f7020" +
	"6669787475726520626f6479200100cc1f4a3d015e2a4d1811000000360000002001" +
	"00000100000000b1ea928f";

function bytesFromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let index = 0; index < bytes.length; index += 1) {
		const pair = hex.slice(index * 2, index * 2 + 2);
		bytes[index] = Number.parseInt(pair, 16);
	}

	return bytes;
}

describe("ZstdCompression", () => {
	const zstd = new ZstdCompression();

	it("round-trips a body under the profile zstd OID", async () => {
		const compressed = await zstd.compress(INTEROP_PAYLOAD);
		expect(compressed.algorithmOid).toBe(PROFILE_OIDS.zstd);

		await expect(zstd.decompress(compressed)).resolves.toEqual(
			INTEROP_PAYLOAD,
		);
	});

	it("opens a stream compressed by tightbeam-rs (zeekstd)", async () => {
		const compressed = {
			algorithmOid: PROFILE_OIDS.zstd,
			data: bytesFromHex(ZEEKSTD_FIXTURE_HEX),
		};

		await expect(zstd.decompress(compressed)).resolves.toEqual(
			INTEROP_PAYLOAD,
		);
	});

	it("splits bodies beyond the 2 MiB frame policy into multiple frames", async () => {
		const large = new Uint8Array(2 * 1024 * 1024 + 1).fill(0x61);

		const compressed = await zstd.compress(large);
		await expect(zstd.decompress(compressed)).resolves.toEqual(large);
	}, 20_000);

	it("rejects a body carried under another algorithm OID", async () => {
		const compressed = await zstd.compress(INTEROP_PAYLOAD);
		const relabeled = { ...compressed, algorithmOid: PROFILE_OIDS.zlib };

		await expect(zstd.decompress(relabeled)).rejects.toThrow(
			ValidationError,
		);
	});

	it("rejects a stream without a seekable seek table", async () => {
		const compressed = {
			algorithmOid: PROFILE_OIDS.zstd,
			data: new Uint8Array(32).fill(0xff),
		};

		await expect(zstd.decompress(compressed)).rejects.toThrow(
			ValidationError,
		);
	});

	it("rejects a declared output size beyond the ceiling before decompressing", async () => {
		const capped = new ZstdCompression(64);
		const compressed = await zstd.compress(INTEROP_PAYLOAD);

		await expect(capped.decompress(compressed)).rejects.toThrow(
			ValidationError,
		);
	});
});

describe("profile zstd through the frame pipeline", () => {
	const zstd = new ZstdCompression();

	it("round-trips a compressed frame body", async () => {
		const built = await frame(BODY).withCompressor(zstd).build();
		expect(built.compressed).toBe(true);
		expect(built.compactnessInfo?.algorithmOid).toBe(PROFILE_OIDS.zstd);

		await expect(built.inflateMessage(zstd, Opaque)).resolves.toEqual(BODY);
	});
});
