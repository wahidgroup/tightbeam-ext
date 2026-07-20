// Bridge the in-page round-trip helpers installed by `app/main.ts` so both the
// app and the Playwright spec (via `page.evaluate`) share one typed interface.
import type {
	RoundTripResult,
	SealedRoundTripResult,
	SignedRoundTripResult,
} from "./app/main.js";

export {};

declare global {
	interface Window {
		tbRoundTrip: (
			url: string,
			payloadHex: string,
			idText: string,
			order: number,
		) => Promise<RoundTripResult>;
		tbSecureRoundTrip: (
			url: string,
			serverCertB64: string,
			payloadHex: string,
			idText: string,
			order: number,
		) => Promise<RoundTripResult>;
		tbMutualRoundTrip: (
			url: string,
			serverCertB64: string,
			clientCertB64: string,
			clientKeyB64: string,
			payloadHex: string,
			idText: string,
			order: number,
		) => Promise<RoundTripResult>;
		tbSignedRoundTrip: (
			url: string,
			payloadHex: string,
			idText: string,
			order: number,
			signingKeyHex: string,
			saltHex: string,
		) => Promise<SignedRoundTripResult>;
		tbSealedRoundTrip: (
			url: string,
			payloadHex: string,
			idText: string,
			order: number,
			keyHex: string,
		) => Promise<SealedRoundTripResult>;
	}
}
