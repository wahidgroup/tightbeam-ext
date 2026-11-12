/**
 * The engine loader of the `node` build condition, as the build section of
 * `docs/ws-wasm.md` describes.
 */

import type { EngineLoader, EngineModule } from "../engine.js";
import { Once } from "../once.js";

/**
 * The import of the glue in this realm.
 */
const started = new Once<EngineModule>();

/**
 * Import the `nodejs` glue, which compiles its binary as it loads.
 */
async function start(): Promise<EngineModule> {
	const glue = await import("../../wasm-node/tightbeam_ws_wasm.js");
	return glue;
}

/**
 * The loader of the `nodejs` glue, which imports the glue once per realm.
 */
export const engineLoader: EngineLoader = {
	load(): Promise<EngineModule> {
		const loading = started.run(start);
		return loading;
	},
};
