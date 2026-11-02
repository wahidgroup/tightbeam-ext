/**
 * Compression capabilities and the tightbeam profile implementation.
 *
 * The tightbeam profile compression is one zstd frame
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
	 * Content-type OID of the uncompressed body. Defaults to `id-data` when
	 * omitted.
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
 * The magic number that opens a zstd frame (RFC 8878 § 3.1.1).
 */
const ZSTD_FRAME_MAGIC = 0xfd2fb528;

/**
 * Octets of the magic number and the frame header descriptor.
 */
const ZSTD_DESCRIPTOR_END = 5;

/**
 * Octets of the window descriptor, which a single-segment frame omits.
 */
const ZSTD_WINDOW_DESCRIPTOR = 1;

/**
 * Octets of `Frame_Content_Size`, by `Frame_Content_Size_flag`.
 */
const CONTENT_SIZE_FIELD = [1, 2, 4, 8] as const;

/**
 * Octets of `Dictionary_ID`, by `Dictionary_ID_flag`.
 */
const DICTIONARY_ID_FIELD = [0, 1, 2, 4] as const;

/**
 * The `Frame_Content_Size` of a two-octet field counts from 256
 * (RFC 8878 § 3.1.1.4).
 */
const TWO_OCTET_CONTENT_SIZE_OFFSET = 256;

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
 * The decompressed size a zstd frame declares in its header, or `undefined`
 * for a frame that declares none or bytes that open no frame
 * (RFC 8878 § 3.1.1.1).
 */
function declaredContentSize(data: Uint8Array): number | undefined {
	if (data.length < ZSTD_DESCRIPTOR_END) {
		return undefined;
	}

	const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	if (view.getUint32(0, true) !== ZSTD_FRAME_MAGIC) {
		return undefined;
	}

	const descriptor = view.getUint8(4);
	const sizeFlag = descriptor >> 6;
	const singleSegment = (descriptor & 0x20) !== 0;
	if (sizeFlag === 0 && !singleSegment) {
		return undefined;
	}

	let offset =
		ZSTD_DESCRIPTOR_END + (DICTIONARY_ID_FIELD[descriptor & 0x03] ?? 0);
	if (!singleSegment) {
		offset += ZSTD_WINDOW_DESCRIPTOR;
	}

	const sizeField = CONTENT_SIZE_FIELD[sizeFlag] ?? 0;
	if (data.length < offset + sizeField) {
		return undefined;
	}

	switch (sizeField) {
		case 1:
			return view.getUint8(offset);
		case 2:
			return view.getUint16(offset, true) + TWO_OCTET_CONTENT_SIZE_OFFSET;
		case 4:
			return view.getUint32(offset, true);
		default:
			return Number(view.getBigUint64(offset, true));
	}
}

/**
 * The tightbeam profile compression: one zstd frame (`PROFILE_OIDS.zstd`).
 * tightbeam-rs `ZstdCompression` refuses any octet past that frame. The libzstd
 * wasm build loads on first use.
 *
 * `maxOutput` bounds decompression, at 16 MiB by default:
 *
 * - A frame that declares a larger size throws `OUTPUT_LIMIT_EXCEEDED` before any allocation.
 * - A frame that declares no size decompresses into a `maxOutput`-octet buffer, and overflow throws.
 *
 * # Sources
 *
 * - RFC 8878, Zstandard Compression and the application/zstd Media Type:
 *   {@link https://datatracker.ietf.org/doc/html/rfc8878 RFC 8878}
 * - CWE-409, Improper Handling of Highly Compressed Data (Data Amplification):
 *   {@link https://cwe.mitre.org/data/definitions/409.html CWE-409}
 */
export class ZstdCompression implements BodyCompressor, BodyInflator {
	constructor(private readonly maxOutput: number = DEFAULT_MAX_OUTPUT) {}

	async compress(bodyDer: Uint8Array): Promise<CompressedBody> {
		const zstd = await zstdModule();

		const data = zstd.compress(bodyDer);
		const compressed = { algorithmOid: PROFILE_OIDS.zstd, data };
		return compressed;
	}

	async decompress(compressed: CompressedBody): Promise<Uint8Array> {
		requireZstd(compressed);

		const declaredOutput = declaredContentSize(compressed.data);
		if (declaredOutput !== undefined && declaredOutput > this.maxOutput) {
			throw new ValidationError("OUTPUT_LIMIT_EXCEEDED", [
				{
					path: "compactness.data",
					message: `Decompressed size ${declaredOutput} exceeds the ${this.maxOutput}-byte ceiling`,
				},
			]);
		}

		const zstd = await zstdModule();
		const bodyDer = zstd.decompress(compressed.data, { defaultHeapSize: this.maxOutput });
		return bodyDer;
	}
}
