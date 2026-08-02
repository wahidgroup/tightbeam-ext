/**
 * Compression capabilities and the tightbeam profile implementation.
 *
 * The tightbeam profile compression is zstd in the seekable format
 * (`PROFILE_OIDS.zstd`), provided by {@link ZstdCompression}. The
 * platform-native `CompressionStream("deflate")` pairs with
 * `PROFILE_OIDS.zlib` for a dependency-free alternative.
 *
 * Inflators SHOULD cap their output size. A wire-supplied body can be a
 * decompression bomb.
 *
 * # Sources
 *
 * - CWE-409, Improper Handling of Highly Compressed Data (Data Amplification):
 *   {@link https://cwe.mitre.org/data/definitions/409.html CWE-409}
 */

import { ValidationError } from "./builder/errors.js";
import { PROFILE_OIDS } from "./crypto.js";

/**
 * A compressed frame body: the pieces installed in the frame's compactness
 * info alongside the compressed bytes.
 */
export interface CompressedBody {
	/**
	 * The dotted OID of the compression algorithm.
	 */
	readonly algorithmOid: string;
	/**
	 * The DER-encoded algorithm parameters, when the scheme has any.
	 */
	readonly parametersDer?: Uint8Array;
	/**
	 * Content-type OID of the uncompressed body. Defaults to
	 * `id-ct-compressedData` when omitted.
	 */
	readonly contentOid?: string;
	/**
	 * The compressed bytes replacing the frame body.
	 */
	readonly data: Uint8Array;
}

/**
 * A body-compression capability. Implement it with any compression library.
 */
export interface BodyCompressor {
	/**
	 * Compress a body DER, resolving with the compressed bytes and the
	 * algorithm identifiers recorded in the frame.
	 */
	compress(bodyDer: Uint8Array): Promise<CompressedBody>;
}

/**
 * A body-decompression capability: receives the carried compactness pieces
 * and resolves with the uncompressed body DER.
 */
export interface BodyInflator {
	/**
	 * Decompress a carried body, resolving with the body DER.
	 *
	 * @throws when the algorithm does not match this implementation or the
	 * bytes are not a valid stream (implementations SHOULD also reject
	 * output exceeding a caller-chosen cap).
	 */
	decompress(compressed: CompressedBody): Promise<Uint8Array>;
}

/**
 * The default decompression ceiling, matching tightbeam-rs
 * `DEFAULT_MAX_DECOMPRESSED_LEN` (16 MiB).
 */
const DEFAULT_MAX_OUTPUT = 16 * 1024 * 1024;

/**
 * Zstd seekable-format framing constants (the layout zeekstd reads and
 * writes: data frames followed by a skippable frame carrying the seek
 * table).
 */
const ZSTD_SKIPPABLE_MAGIC = 0x184d2a5e;
const SEEKABLE_MAGIC = 0x8f92eab1;
const SKIPPABLE_HEADER_SIZE = 8;
const SEEK_TABLE_FOOTER_SIZE = 9;
const CHECKSUM_FLAG = 0x80;

/**
 * Uncompressed bytes per seekable frame, matching zeekstd's default frame
 * size policy (2 MiB).
 */
const FRAME_CHUNK = 0x20_0000;

/**
 * A parsed seek-table entry: the compressed and decompressed size of one
 * data frame.
 */
interface SeekFrame {
	readonly cSize: number;
	readonly dSize: number;
}

/**
 * The zstd module surface consumed by {@link ZstdCompression}.
 */
interface ZstdModule {
	compress(data: Uint8Array, level?: number): Uint8Array;
	decompress(
		data: Uint8Array,
		options?: { defaultHeapSize?: number },
	): Uint8Array;
}

let zstdLoading: Promise<ZstdModule> | undefined;

/**
 * Load and initialize the bundled libzstd wasm module once. Subsequent
 * calls await the same load. The load is lazy, so clients that never
 * compress never pay for it.
 */
function zstdModule(): Promise<ZstdModule> {
	if (zstdLoading === undefined) {
		zstdLoading = (async (): Promise<ZstdModule> => {
			const zstd = await import("@bokuweb/zstd-wasm");
			await zstd.init();
			return zstd;
		})();
	}

	return zstdLoading;
}

/**
 * Reject a carried body whose algorithm OID is not the profile zstd OID.
 */
function requireZstd(compressed: CompressedBody): void {
	if (compressed.algorithmOid !== PROFILE_OIDS.zstd) {
		throw new ValidationError("ALGORITHM_MISMATCH", [
			{
				path: "compactness.algorithmOid",
				message: `Compressed with ${compressed.algorithmOid}, but this inflator opens ${PROFILE_OIDS.zstd}`,
			},
		]);
	}
}

/**
 * Fail seek-table parsing with a uniform validation error.
 */
function malformedSeekTable(message: string): ValidationError {
	const error = new ValidationError("ZSTD_SEEK_TABLE", [
		{ path: "compactness.data", message },
	]);
	return error;
}

/**
 * Parse the seekable-format seek table trailing `data`: the frame sizes
 * zeekstd records, needed to size and split decompression.
 */
function parseSeekTable(data: Uint8Array): SeekFrame[] {
	const minimumSize = SKIPPABLE_HEADER_SIZE + SEEK_TABLE_FOOTER_SIZE;
	if (data.length < minimumSize) {
		throw malformedSeekTable("Too short for a seekable zstd stream");
	}

	const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	const footerStart = data.length - SEEK_TABLE_FOOTER_SIZE;
	const seekableMagic = view.getUint32(footerStart + 5, true);
	if (seekableMagic !== SEEKABLE_MAGIC) {
		throw malformedSeekTable("Missing the seekable-format magic number");
	}

	const frameCount = view.getUint32(footerStart, true);
	const descriptor = view.getUint8(footerStart + 4);
	let sizePerFrame = 8;
	if ((descriptor & CHECKSUM_FLAG) !== 0) {
		sizePerFrame = 12;
	}

	const seekTableSize =
		frameCount * sizePerFrame +
		SKIPPABLE_HEADER_SIZE +
		SEEK_TABLE_FOOTER_SIZE;
	if (data.length < seekTableSize) {
		throw malformedSeekTable("Seek table longer than the stream");
	}

	const tableStart = data.length - seekTableSize;
	const skippableMagic = view.getUint32(tableStart, true);
	if (skippableMagic !== ZSTD_SKIPPABLE_MAGIC) {
		throw malformedSeekTable("Missing the seek-table skippable frame");
	}

	const declaredFrameSize = view.getUint32(tableStart + 4, true);
	const expectedFrameSize = seekTableSize - SKIPPABLE_HEADER_SIZE;
	if (declaredFrameSize !== expectedFrameSize) {
		throw malformedSeekTable("Seek-table size field mismatch");
	}

	const frames: SeekFrame[] = [];
	let dataOffset = 0;
	for (let index = 0; index < frameCount; index += 1) {
		const entry = tableStart + SKIPPABLE_HEADER_SIZE + index * sizePerFrame;
		const frame = {
			cSize: view.getUint32(entry, true),
			dSize: view.getUint32(entry + 4, true),
		};

		frames.push(frame);

		dataOffset += frame.cSize;
	}

	if (dataOffset !== tableStart) {
		throw malformedSeekTable("Frame sizes do not cover the data region");
	}

	return frames;
}

/**
 * Serialize a zeekstd-layout seek table for `frames`: skippable header,
 * one `(cSize, dSize)` entry per frame, and the integrity footer.
 */
function serializeSeekTable(frames: SeekFrame[]): Uint8Array {
	const entriesSize = frames.length * 8;
	const skippableFrameSize = entriesSize + SEEK_TABLE_FOOTER_SIZE;
	const tableSize = SKIPPABLE_HEADER_SIZE + skippableFrameSize;
	const table = new Uint8Array(tableSize);
	const view = new DataView(table.buffer);

	view.setUint32(0, ZSTD_SKIPPABLE_MAGIC, true);
	view.setUint32(4, skippableFrameSize, true);

	for (const [index, frame] of frames.entries()) {
		const entry = SKIPPABLE_HEADER_SIZE + index * 8;
		view.setUint32(entry, frame.cSize, true);
		view.setUint32(entry + 4, frame.dSize, true);
	}

	const footerStart = SKIPPABLE_HEADER_SIZE + entriesSize;
	view.setUint32(footerStart, frames.length, true);
	view.setUint8(footerStart + 4, 0);
	view.setUint32(footerStart + 5, SEEKABLE_MAGIC, true);

	return table;
}

/**
 * The tightbeam profile compression: zstd in the seekable format
 * (`PROFILE_OIDS.zstd`), wire-compatible with tightbeam-rs `ZstdCompression`
 * (zeekstd). Backed by a lazily loaded wasm build of libzstd.
 *
 * Decompression is bounded. The seek table's declared output size is checked
 * against `maxOutput` (default 16 MiB, matching tightbeam-rs) before any
 * allocation, so a wire-supplied decompression bomb is rejected up front.
 *
 * # Sources
 *
 * - CWE-409, Improper Handling of Highly Compressed Data (Data Amplification):
 *   {@link https://cwe.mitre.org/data/definitions/409.html CWE-409}
 */
export class ZstdCompression implements BodyCompressor, BodyInflator {
	constructor(private readonly maxOutput: number = DEFAULT_MAX_OUTPUT) {}

	async compress(bodyDer: Uint8Array): Promise<CompressedBody> {
		const zstd = await zstdModule();

		// One seekable frame per 2 MiB of input, zeekstd's default policy.
		const chunks: Uint8Array[] = [];
		for (let offset = 0; offset < bodyDer.length; offset += FRAME_CHUNK) {
			chunks.push(bodyDer.subarray(offset, offset + FRAME_CHUNK));
		}

		if (chunks.length === 0) {
			chunks.push(new Uint8Array());
		}

		const frames: SeekFrame[] = [];
		const parts: Uint8Array[] = [];
		for (const chunk of chunks) {
			const part = zstd.compress(chunk);

			parts.push(part);
			frames.push({ cSize: part.length, dSize: chunk.length });
		}

		const seekTable = serializeSeekTable(frames);
		parts.push(seekTable);

		const data = concat(parts);
		const compressed = { algorithmOid: PROFILE_OIDS.zstd, data };
		return compressed;
	}

	async decompress(compressed: CompressedBody): Promise<Uint8Array> {
		requireZstd(compressed);

		const frames = parseSeekTable(compressed.data);
		const declaredOutput = frames.reduce(
			(sum, frame) => sum + frame.dSize,
			0,
		);

		if (declaredOutput > this.maxOutput) {
			throw new ValidationError("OUTPUT_LIMIT_EXCEEDED", [
				{
					path: "compactness.data",
					message: `Decompressed size ${declaredOutput} exceeds the ${this.maxOutput}-byte ceiling`,
				},
			]);
		}

		const zstd = await zstdModule();
		const bodyDer = new Uint8Array(declaredOutput);
		let inOffset = 0;
		let outOffset = 0;
		for (const frame of frames) {
			const frameBytes = compressed.data.subarray(
				inOffset,
				inOffset + frame.cSize,
			);
			const heapSize = Math.max(frame.dSize, 1);
			const part = zstd.decompress(frameBytes, {
				defaultHeapSize: heapSize,
			});
			if (part.length !== frame.dSize) {
				throw malformedSeekTable(
					"Frame decompressed to a size other than the seek table declares",
				);
			}

			bodyDer.set(part, outOffset);

			inOffset += frame.cSize;
			outOffset += frame.dSize;
		}

		return bodyDer;
	}
}

/**
 * Concatenate byte parts into one buffer.
 */
function concat(parts: Uint8Array[]): Uint8Array {
	const total = parts.reduce((sum, part) => sum + part.length, 0);
	const joined = new Uint8Array(total);
	let offset = 0;
	for (const part of parts) {
		joined.set(part, offset);

		offset += part.length;
	}

	return joined;
}
