// Bridge the in-page round-trip helper installed by `app/main.ts` so both the
// app and the Playwright spec (via `page.evaluate`) share one typed interface.
import type { RoundTripResult } from "./app/main.js";

export {};

declare global {
	interface Window {
		tbRoundTrip: (
			url: string,
			payloadHex: string,
			idText: string,
			order: number,
		) => Promise<RoundTripResult>;
	}
}
