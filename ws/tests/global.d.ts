// Types the api objects that `app/main.ts` and `app/engine.ts` install, so the
// pages and the Playwright specs (via `page.evaluate`) share one interface.
import type { EngineApi } from "./app/engine.js";
import type { PageApi } from "./app/main.js";

export {};

declare global {
	interface Window {
		tb: PageApi;
		tbEngine: EngineApi;
	}
}
