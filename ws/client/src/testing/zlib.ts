/**
 * A zlib compression that the unit tests bring, over the platform `CompressionStream("deflate")`.
 */

import type { BodyCompressor, BodyInflator, CompressedBody } from "../compress.js";
import type { Engine } from "../engine.js";
import type { OidName } from "../views.js";

/**
 * Run `bytes` through a compression or decompression transform stream.
 */
async function pump(transform: ReadableWritablePair<Uint8Array, BufferSource>, bytes: Uint8Array): Promise<Uint8Array> {
	const input = new Uint8Array(bytes);
	const source = new Blob([input]).stream().pipeThrough(transform);

	const collected = await new Response(source).arrayBuffer();
	const output = new Uint8Array(collected);
	return output;
}

/**
 * A zlib {@link BodyCompressor} and {@link BodyInflator} that the platform
 * implements, as a caller brings any compression library.
 */
export class ZlibCompression implements BodyCompressor, BodyInflator {
	/**
	 * The zlib algorithm of the profile, which the engine names.
	 */
	readonly algorithmOid: OidName;

	constructor(engine: Engine) {
		this.algorithmOid = engine.profile.zlib;
	}

	async compress(bodyDer: Uint8Array): Promise<CompressedBody> {
		const data = await pump(new CompressionStream("deflate"), bodyDer);
		const compressed = { data };
		return compressed;
	}

	/**
	 * Whether `parametersDer` are absent, because zlib defines no parameters.
	 */
	admitsParameters(parametersDer?: Uint8Array): boolean {
		const admitted = parametersDer === undefined;
		return admitted;
	}

	async decompress(data: Uint8Array): Promise<Uint8Array> {
		const bodyDer = await pump(new DecompressionStream("deflate"), data);
		return bodyDer;
	}
}
