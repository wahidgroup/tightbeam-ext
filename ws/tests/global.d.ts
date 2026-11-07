// Bridge the in-page helpers installed by `app/main.ts` and `app/engine.ts` so
// both the pages and the Playwright specs (via `page.evaluate`) share one typed
// interface.
// Each entry takes the type of the function the app installs.
import type {
	compressedRoundTrip,
	compressedSealedRoundTrip,
	muxCallbackRoundTrip,
	muxClearConcurrentRoundTrip,
	muxConcurrentRoundTrip,
	muxDrainReason,
	muxLifecycleProbe,
	muxParkedCallbackRoundTrip,
	muxRefusalRoundTrip,
	mutualRoundTrip,
	mutualSignerRoundTrip,
	roundTrip,
	sealedRoundTrip,
	secureRoundTrip,
	signedRoundTrip,
	streamingRoundTrip,
	typedRoundTrip,
	workRefusal,
	workRoundTrip,
} from "./app/main.js";
import type { initRefusal, initWithInput } from "./app/engine.js";

export {};

declare global {
	interface Window {
		tbRoundTrip: typeof roundTrip;
		tbSecureRoundTrip: typeof secureRoundTrip;
		tbMutualRoundTrip: typeof mutualRoundTrip;
		tbMutualSignerRoundTrip: typeof mutualSignerRoundTrip;
		tbStreamingRoundTrip: typeof streamingRoundTrip;
		tbSignedRoundTrip: typeof signedRoundTrip;
		tbSealedRoundTrip: typeof sealedRoundTrip;
		tbCompressedRoundTrip: typeof compressedRoundTrip;
		tbCompressedSealedRoundTrip: typeof compressedSealedRoundTrip;
		tbTypedRoundTrip: typeof typedRoundTrip;
		tbMuxConcurrentRoundTrip: typeof muxConcurrentRoundTrip;
		tbMuxCallbackRoundTrip: typeof muxCallbackRoundTrip;
		tbMuxClearConcurrentRoundTrip: typeof muxClearConcurrentRoundTrip;
		tbMuxLifecycleProbe: typeof muxLifecycleProbe;
		tbMuxDrainReason: typeof muxDrainReason;
		tbMuxParkedCallbackRoundTrip: typeof muxParkedCallbackRoundTrip;
		tbMuxRefusalRoundTrip: typeof muxRefusalRoundTrip;
		tbWorkRoundTrip: typeof workRoundTrip;
		tbWorkRefusal: typeof workRefusal;
		tbInitWithInput: typeof initWithInput;
		tbInitRefusal: typeof initRefusal;
	}
}
