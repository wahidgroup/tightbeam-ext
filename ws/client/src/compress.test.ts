import { describe, expect, it } from "vitest";

import { TightbeamWsClient } from "./index.js";

/**
 * The engine zstd compression: one frame, with the refusals the engine names,
 * on its own and on the inflate path of a frame.
 */

const engine = await TightbeamWsClient.init();

const BODY = new Uint8Array([1, 2, 3, 4]);

/**
 * A payload that compresses well, so its frame is short.
 */
const PAYLOAD = new Uint8Array(4096).fill(0x61);

/**
 * A ceiling below the 128 KiB window ruzstd 0.9.0 declares, which refuses
 * every body the engine compressed.
 */
const SMALL_CEILING = 64;

/**
 * A ceiling whose rounded window holds the 128 KiB window ruzstd declares,
 * and which {@link LARGE_PAYLOAD} outgrows.
 */
const WINDOW_CEILING = 200 * 1024;

/**
 * A payload past {@link WINDOW_CEILING}.
 */
const LARGE_PAYLOAD = new Uint8Array(300 * 1024).fill(0x62);

/**
 * A ceiling that holds {@link LARGE_PAYLOAD}.
 */
const HOLDING_CEILING = 400 * 1024;

/**
 * Octets that open no zstd frame.
 */
const NO_FRAME = new Uint8Array(32).fill(0xff);

/**
 * The profile zstd at the default ceiling.
 */
const zstd = engine.zstd();

/**
 * The compressed octets of {@link PAYLOAD}.
 */
const PACKED = zstd.compress(PAYLOAD).data;

/**
 * {@link PACKED} with its last octet cut.
 */
const TRUNCATED = PACKED.slice(0, -1);

/**
 * {@link PACKED} with one octet after the frame.
 */
const TRAILING = new Uint8Array([...PACKED, 0]);

describe("ZstdCompression", () => {
	it("two views over one handle each enforce their own ceiling", () => {
		const lower = engine.zstd(WINDOW_CEILING);
		const higher = engine.zstd(HOLDING_CEILING);

		const compressed = zstd.compress(LARGE_PAYLOAD);
		expect(() => lower.decompress(compressed.data)).toThrow(
			expect.objectContaining({ code: "OutputLimitExceeded" }),
		);
		expect(higher.decompress(compressed.data)).toEqual(LARGE_PAYLOAD);
	});

	it("round-trips a body", () => {
		const compressed = zstd.compress(PAYLOAD);
		expect(zstd.decompress(compressed.data)).toEqual(PAYLOAD);
	});

	it("names the profile zstd OID as the algorithm it reverses", () => {
		expect(zstd.algorithmOid.equals(engine.profile.zstd)).toBe(true);
	});

	it("round-trips a body past one megabyte", () => {
		const large = new Uint8Array(2 * 1024 * 1024 + 1).fill(0x61);
		const compressed = zstd.compress(large);
		expect(zstd.decompress(compressed.data)).toEqual(large);
	}, 20_000);

	it.each([
		{ name: "bytes that open no frame", data: NO_FRAME, code: "Malformed" },
		{ name: "a frame cut short", data: TRUNCATED, code: "Truncated" },
		{
			name: "an octet after the frame",
			data: TRAILING,
			code: "TrailingBytes",
		},
	])("refuses $name with $code", ({ data, code }) => {
		expect(() => zstd.decompress(data)).toThrow(
			expect.objectContaining({ code }),
		);
	});

	it("refuses a window past the ceiling with WindowTooLarge", () => {
		const capped = engine.zstd(SMALL_CEILING);
		expect(() => capped.decompress(PACKED)).toThrow(
			expect.objectContaining({ code: "WindowTooLarge" }),
		);
	});

	it("refuses output past the ceiling with OutputLimitExceeded", () => {
		const capped = engine.zstd(WINDOW_CEILING);
		const compressed = zstd.compress(LARGE_PAYLOAD);
		expect(() => capped.decompress(compressed.data)).toThrow(
			expect.objectContaining({ code: "OutputLimitExceeded" }),
		);
	});

	it.each([
		{ name: "NaN", maxOutput: Number.NaN },
		{ name: "a negative ceiling", maxOutput: -1 },
		{ name: "a fraction", maxOutput: 1.5 },
	])("refuses $name as a ceiling with InvalidMaxOutput", ({ maxOutput }) => {
		expect(() => engine.zstd(maxOutput)).toThrow(
			expect.objectContaining({ code: "InvalidMaxOutput" }),
		);
	});
});

describe("ZstdCompression.admitsParameters", () => {
	it.each([
		{ name: "no parameters", parametersDer: undefined, admitted: true },
		{
			name: "the default level",
			parametersDer: new Uint8Array([0x02, 0x01, 0x03]),
			admitted: true,
		},
		{
			name: "the highest level",
			parametersDer: new Uint8Array([0x02, 0x01, 0x16]),
			admitted: true,
		},
		{
			name: "the lowest level",
			parametersDer: new Uint8Array([0x02, 0x03, 0xfe, 0x00, 0x00]),
			admitted: true,
		},
		{
			name: "a level above the range",
			parametersDer: new Uint8Array([0x02, 0x01, 0x17]),
			admitted: false,
		},
		{
			name: "a level below the range",
			parametersDer: new Uint8Array([0x02, 0x03, 0xfd, 0xff, 0xff]),
			admitted: false,
		},
		{
			name: "a padded integer",
			parametersDer: new Uint8Array([0x02, 0x02, 0x00, 0x03]),
			admitted: false,
		},
		{
			name: "a NULL",
			parametersDer: new Uint8Array([0x05, 0x00]),
			admitted: false,
		},
	])("reads $name as admitted: $admitted", ({ parametersDer, admitted }) => {
		expect(zstd.admitsParameters(parametersDer)).toBe(admitted);
	});
});

describe("profile zstd through the frame pipeline", () => {
	it("round-trips a compressed frame body", async () => {
		const builder = engine.frameBuilder(BODY).withCompressor(zstd);
		const built = await builder.build();
		const algorithm = built.compactnessInfo?.algorithmOid;

		expect(built.compressed).toBe(true);
		expect(algorithm?.equals(engine.profile.zstd)).toBe(true);
		await expect(
			built.inflateMessage(zstd, engine.opaque),
		).resolves.toEqual(BODY);
	});

	it("opens a compressed frame body through an inflator", async () => {
		const builder = engine.frameBuilder(BODY).withCompressor(zstd);
		const built = await builder.build();

		const opened = built.open(engine.opaque, { inflator: zstd });
		await expect(opened).resolves.toEqual(BODY);
	});

	it("a zstd refusal on the frame inflate path carries CompressionError", async () => {
		const builder = engine.frameBuilder(PAYLOAD).withCompressor(zstd);
		const built = await builder.build();
		const capped = engine.zstd(SMALL_CEILING);

		const inflated = built.inflateMessage(capped, engine.opaque);
		await expect(inflated).rejects.toMatchObject({
			code: "CompressionError",
		});
		expect(() => capped.decompress(built.bodyDer)).toThrow(
			expect.objectContaining({ code: "WindowTooLarge" }),
		);
	});
});
