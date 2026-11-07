/**
 * The engine loader of the `default` build condition: the `web` glue, which
 * fetches or compiles its binary when its `init` runs.
 */

import type { EngineInput, EngineLoader, EngineModule } from "../engine.js";

/**
 * Import the `web` glue and start it from `input`: a URL, a `Response`, the
 * bytes, or a compiled `WebAssembly.Module`. Without `input`, the glue fetches
 * the binary that sits beside it.
 *
 * The glue keeps one instance per realm, and a second start in flight would
 * swap that instance under live handles. `Engine.load` is the one caller of
 * this loader, and its memo starts the glue once per realm.
 */
export const engineLoader: EngineLoader = {
	async load(input?: EngineInput): Promise<EngineModule> {
		const glue = await import("../../wasm/tightbeam_ws_wasm.js");
		if (input === undefined) {
			await glue.default();
		} else {
			await glue.default({ module_or_path: input });
		}

		return glue;
	},
};
