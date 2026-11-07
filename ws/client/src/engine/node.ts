/**
 * The engine loader of the `node` build condition. The `nodejs` glue reads
 * its binary from beside itself as it loads, so the loader takes no input.
 */

import type { EngineLoader, EngineModule } from "../engine.js";

/**
 * Import the `nodejs` glue, which compiles its binary as it loads.
 */
export const engineLoader: EngineLoader = {
	async load(): Promise<EngineModule> {
		const glue = await import("../../wasm-node/tightbeam_ws_wasm.js");
		return glue;
	},
};
