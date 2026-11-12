/**
 * The compression capabilities of a frame body, as the compression section of `docs/ws-client.md` describes.
 */

import type { CompressedBody, ZstdCompression } from "#wasm";

import type { CompactnessInfo } from "./frame.js";
import type { OidName } from "./views.js";
import { ClientTransportError } from "./errors.js";
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
	 * Compress a body DER, answering the compressed bytes and the parameters the algorithm defines.
	 *
	 * @throws any error of the implementation, as a throw or a rejection. It rejects the build.
	 */
	readonly compress: (bodyDer: Uint8Array) => CompressedBody | Promise<CompressedBody>;
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
	 * Whether `parametersDer`, the parameters that the compactness info of a frame names, take a form this algorithm
	 * defines, such as a level inside its valid range. `Frame.open` asks before it decrypts or inflates.
	 *
	 * @throws any error of the implementation, which rejects the `Frame.open`.
	 */
	readonly admitsParameters: (parametersDer?: Uint8Array) => boolean;

	/**
	 * Decompress compressed bytes, answering the body DER.
	 *
	 * @throws when the bytes are not a valid stream (implementations SHOULD
	 * also refuse output past a caller-chosen cap).
	 */
	readonly decompress: (data: Uint8Array) => Uint8Array | Promise<Uint8Array>;
}

/**
 * A compressor held past the call that received it: the compression of the
 * caller's compressor, under a copy of the algorithm it names. Every frame
 * records that algorithm, the caller keeps its own handle, and the glue
 * reclaims the copy with the holder.
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
 * An inflator as the client holds it: the caller's inflator, under the name
 * of the algorithm it reverses. It owns the decision whether it reverses a
 * compressed body.
 */
export class HeldInflator implements BodyInflator {
	readonly algorithmOid: OidName;

	readonly #inflator: BodyInflator;

	private constructor(inflator: BodyInflator, algorithmOid: OidName) {
		this.algorithmOid = algorithmOid;
		this.#inflator = inflator;
	}

	/**
	 * `inflator`, held past the call that received it under a copy of the
	 * algorithm it names, as {@link HeldCompressor} holds its copy.
	 */
	static copyOf(inflator: BodyInflator): HeldInflator {
		const algorithmOid = OidView.copyOf(inflator.algorithmOid);
		const held = new HeldInflator(inflator, algorithmOid);
		return held;
	}

	/**
	 * `inflator`, held for one call under the name the caller keeps.
	 */
	static lent(inflator: BodyInflator): HeldInflator {
		const held = new HeldInflator(inflator, inflator.algorithmOid);
		return held;
	}

	admitsParameters(parametersDer?: Uint8Array): boolean {
		const admitted = this.#inflator.admitsParameters(parametersDer);
		return admitted;
	}

	decompress(data: Uint8Array): Uint8Array | Promise<Uint8Array> {
		const inflated = this.#inflator.decompress(data);
		return inflated;
	}

	/**
	 * The inflation of a body that `compactness` describes.
	 *
	 * @throws TightbeamTransportError `CompactnessRefused` at `compactness`
	 * when the inflator names another algorithm, or refuses the parameters.
	 */
	admit(compactness: CompactnessInfo): Inflation {
		const algorithm = compactness.algorithmOid;
		const reverses = algorithm.equals(this.algorithmOid);
		const parameters = compactness.parametersDer;
		if (!reverses || !this.#inflator.admitsParameters(parameters)) {
			throw ClientTransportError.compactnessRefused(algorithm.toString());
		}

		const inflation = new Inflation(this.#inflator);
		return inflation;
	}
}

/**
 * The inflation an inflator admitted for one compressed body. The module
 * exports its type alone, so {@link HeldInflator.admit} is its one creator.
 */
class Inflation {
	readonly #inflator: BodyInflator;

	constructor(inflator: BodyInflator) {
		this.#inflator = inflator;
	}

	/**
	 * The body DER that `data`, the compressed body, inflates to.
	 */
	async inflate(data: Uint8Array): Promise<Uint8Array> {
		const bodyDer = await this.#inflator.decompress(data);
		return bodyDer;
	}
}

export type { Inflation };

/**
 * The engine zstd at one ceiling, which `Engine.zstd` lends. The view holds
 * the wasm handle that the engine bound to the ceiling, and the glue reclaims
 * that handle with the view.
 */
export class ZstdView implements BodyCompressor, BodyInflator {
	/**
	 * The profile zstd, which this compression applies and reverses.
	 */
	readonly algorithmOid: OidView;

	readonly #zstd: ZstdCompression;

	private constructor(zstd: ZstdCompression, algorithmOid: OidView) {
		this.#zstd = zstd;
		this.algorithmOid = algorithmOid;
	}

	/**
	 * A view of `zstd`, a handle bound to its ceiling, applying
	 * `algorithmOid`.
	 */
	static over(zstd: ZstdCompression, algorithmOid: OidView): ZstdView {
		const view = new ZstdView(zstd, algorithmOid);
		return view;
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
		const inflated = this.#zstd.decompress(data);
		return inflated;
	}
}
