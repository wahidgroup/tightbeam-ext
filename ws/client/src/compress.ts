/**
 * Compression capabilities.
 *
 * - The profile compression is zstd, which the engine implements
 *   (`Engine.zstd`), so the browser admits the compressed bodies a native
 *   peer admits.
 * - The platform-native `CompressionStream("deflate")` pairs with the zlib
 *   OID of the profile for a dependency-free alternative.
 * - Inflators SHOULD cap their output size, because a wire-supplied body can
 *   be a decompression bomb.
 *
 * # Sources
 *
 * - CWE-409, Improper Handling of Highly Compressed Data (Data Amplification):
 *   {@link https://cwe.mitre.org/data/definitions/409.html CWE-409}
 */

import type { CompressedBody, ZstdCompression } from "#wasm";

import type { OidName } from "./views.js";
import { OidView } from "./views.js";

export type { CompressedBody } from "#wasm";

/**
 * A body-compression capability, in the shape of the tightbeam-rs
 * `Compressor`: the algorithm it applies, and the compression. Implement it
 * with any compression library.
 */
export interface BodyCompressor {
	/**
	 * The compression algorithm this compressor applies, which the frame
	 * records. `withCompressor` copies it once.
	 */
	readonly algorithmOid: OidName;

	/**
	 * Compress a body DER, answering the compressed bytes and the parameters
	 * the algorithm defines.
	 */
	compress(bodyDer: Uint8Array): CompressedBody | Promise<CompressedBody>;
}

/**
 * A body-decompression capability, in the shape of the tightbeam-rs
 * `Inflator`: the algorithm it reverses, the parameters it admits, and the
 * decompression.
 */
export interface BodyInflator {
	/**
	 * The compression algorithm this inflator reverses.
	 */
	readonly algorithmOid: OidName;

	/**
	 * Whether `parametersDer`, the parameters the compactness info of a frame
	 * names for {@link algorithmOid}, take a form this algorithm defines, such
	 * as a level inside its valid range.
	 *
	 * `Frame.open` asks before it decrypts or inflates anything, so a body
	 * no inflator reverses costs no work.
	 */
	admitsParameters(parametersDer?: Uint8Array): boolean;

	/**
	 * Decompress compressed bytes, answering the body DER.
	 *
	 * @throws when the bytes are not a valid stream (implementations SHOULD
	 * also refuse output past a caller-chosen cap).
	 */
	decompress(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/**
 * A compressor held past the call that received it: the compression of the
 * caller's compressor, under a copy of the algorithm it names. Every frame
 * records that algorithm, and the caller keeps its own handle. The holder
 * has no release, so the glue reclaims the copy with it.
 */
export class HeldCompressor implements BodyCompressor {
	readonly algorithmOid: OidView;

	readonly #compressor: BodyCompressor;

	constructor(compressor: BodyCompressor) {
		this.algorithmOid = OidView.copyOf(compressor.algorithmOid);
		this.#compressor = compressor;
	}

	compress(bodyDer: Uint8Array): CompressedBody | Promise<CompressedBody> {
		const compressed = this.#compressor.compress(bodyDer);
		return compressed;
	}
}

/**
 * An inflator held past the call that received it: the inflation of the
 * caller's inflator, under a copy of the algorithm it names, held as
 * {@link HeldCompressor} holds its copy.
 */
export class HeldInflator implements BodyInflator {
	readonly algorithmOid: OidView;

	readonly #inflator: BodyInflator;

	constructor(inflator: BodyInflator) {
		this.algorithmOid = OidView.copyOf(inflator.algorithmOid);
		this.#inflator = inflator;
	}

	admitsParameters(parametersDer?: Uint8Array): boolean {
		const admitted = this.#inflator.admitsParameters(parametersDer);
		return admitted;
	}

	decompress(data: Uint8Array): Uint8Array | Promise<Uint8Array> {
		const inflated = this.#inflator.decompress(data);
		return inflated;
	}
}

/**
 * The key of the ceiling a {@link ZstdView} inflates within, which the frame
 * inflate path reads. The package exports no path to it, so the ceiling
 * stays inside the package.
 */
export const CEILING: unique symbol = Symbol("ceiling");

/**
 * The engine zstd of one realm at one ceiling, which `Engine.zstd` lends.
 *
 * The realm owns the one handle every view reaches, so the view has no
 * `free` and no `[Symbol.dispose]`. The view holds the ceiling the engine
 * parsed once, and each inflate passes it to the engine, so a ceiling leaves
 * no handle behind.
 */
export class ZstdView implements BodyCompressor, BodyInflator {
	/**
	 * The profile zstd, which this compression applies and reverses.
	 */
	readonly algorithmOid: OidView;

	readonly #zstd: ZstdCompression;

	/**
	 * The largest output an inflate yields, in octets.
	 */
	readonly #ceiling: number;

	private constructor(
		zstd: ZstdCompression,
		algorithmOid: OidView,
		ceiling: number,
	) {
		this.#zstd = zstd;
		this.algorithmOid = algorithmOid;
		this.#ceiling = ceiling;
	}

	/**
	 * A view of `zstd`, which the realm owns, applying `algorithmOid` and
	 * inflating within `ceiling`, a whole number the engine parsed.
	 */
	static over(
		zstd: ZstdCompression,
		algorithmOid: OidView,
		ceiling: number,
	): ZstdView {
		const view = new ZstdView(zstd, algorithmOid, ceiling);
		return view;
	}

	/**
	 * The ceiling of each inflate, for the frame inflate path.
	 */
	get [CEILING](): number {
		return this.#ceiling;
	}

	/**
	 * Whether `parametersDer` take a form zstd defines: absent, or a level
	 * inside the range libzstd accepts.
	 */
	admitsParameters(parametersDer?: Uint8Array): boolean {
		const admitted = this.#zstd.admitsParameters(parametersDer);
		return admitted;
	}

	/**
	 * Compress `bodyDer` at the `Fastest` level of ruzstd.
	 */
	compress(bodyDer: Uint8Array): CompressedBody {
		const compressed = this.#zstd.compress(bodyDer);
		return compressed;
	}

	/**
	 * Inflate `data`, which holds exactly one frame, within the ceiling.
	 *
	 * @throws TightbeamTransportError whose `code` names the `ZstdRefusal`:
	 * `WindowTooLarge`, `OutputLimitExceeded`, `Truncated`, `TrailingBytes`,
	 * `Stalled`, or `Malformed`.
	 */
	decompress(data: Uint8Array): Uint8Array {
		const inflated = this.#zstd.decompress(data, this.#ceiling);
		return inflated;
	}
}
