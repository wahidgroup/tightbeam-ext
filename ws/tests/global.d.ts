// Bridge the in-page round-trip helpers installed by `app/main.ts` so both the
// app and the Playwright spec (via `page.evaluate`) share one typed interface.
import type {
	CompressedRoundTripResult,
	RoundTripResult,
	SealedRoundTripResult,
	SignedRoundTripResult,
	TypedRoundTripResult,
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
		tbCompressedRoundTrip: (
			url: string,
			payloadHex: string,
			idText: string,
			order: number,
		) => Promise<CompressedRoundTripResult>;
		tbCompressedSealedRoundTrip: (
			url: string,
			payloadHex: string,
			idText: string,
			order: number,
			keyHex: string,
		) => Promise<CompressedRoundTripResult>;
		tbTypedRoundTrip: (
			url: string,
			idText: string,
			order: number,
			author: string,
			text: string,
		) => Promise<TypedRoundTripResult>;
	}
}
