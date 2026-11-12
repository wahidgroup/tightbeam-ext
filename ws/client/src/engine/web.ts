/**
 * The engine loader of the `default` build condition: the `web` glue, which
 * fetches or compiles its binary when its `init` runs.
 */

import type { EngineInput, EngineLoader, EngineModule } from "../engine.js";
import { Once } from "../once.js";

/**
 * The start of the glue in this realm.
 */
const started = new Once<EngineModule>();

/**
 * Import the `web` glue and start it from `input`: a URL, a `Response`, the
 * bytes, or a compiled `WebAssembly.Module`. Without `input`, the glue fetches
 * the binary that sits beside it.
 */
async function start(input?: EngineInput): Promise<EngineModule> {
	const glue = await import("../../wasm/tightbeam_ws_wasm.js");
	if (input === undefined) {
		await glue.default();
	} else {
		await glue.default({ module_or_path: input });
	}

	return glue;
}

/**
 * The loader of the `web` glue, which starts the glue once per realm.
 */
export const engineLoader: EngineLoader = {
	load(input?: EngineInput): Promise<EngineModule> {
		const loading = started.run(() => start(input));
		return loading;
	},
};
