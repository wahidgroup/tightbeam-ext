/**
 * The round-trip page of the e2e app, whose round trips the specs reach as
 * `window.tb`, as `docs/ws.md` (Test support) states it.
 */

import type {
	Engine,
	Frame,
	MutualIdentity,
	Secp256k1SigningKey,
	TightbeamWsClient,
} from "@wahidgroup/tightbeam-ws-client";
import { Engine as Engines, StreamRefusal } from "@wahidgroup/tightbeam-ws-client";

import type { EmitClient, Note, StackPaywall } from "../fixtures.js";
import { DialFacts, EchoDials, NotePayload, SEAL_SECRET, bytesToHex, hexToBytes } from "../fixtures.js";
import { NobleTransportSigner } from "../signer.js";
import { base64ToBytes } from "../util.js";

const TEXT = new TextDecoder();

/**
 * The stream cap and the demo paywall of the stack, from the query string
 * that the spec opened the page with.
 */
const DIAL = DialFacts.fromQuery(window.location.search);

/**
 * The engine every round-trip of the page builds, parses, and dials with.
 */
const ENGINE = await Engines.load();

/**
 * The typed body codec for a note: JSON in the profile opaque wrapper.
 */
const NOTES = ENGINE.wrapping(NotePayload);

/**
 * The decoded outcome of a single round-trip, in a structured-clone-safe shape
 * (no `bigint`) so it crosses the Playwright `page.evaluate` boundary.
 */
export interface RoundTripResult {
	/**
	 * The opened body of the response, in hex.
	 */
	readonly bodyHex: string;

	/**
	 * The protocol version of the response frame.
	 */
	readonly version: number;

	/**
	 * The id of the response frame, as text.
	 */
	readonly idText: string;

	/**
	 * The order of the response frame, in decimal, because a `bigint` cannot
	 * cross the boundary.
	 */
	readonly order: string;

	/**
	 * Whether the response frame carries a signature.
	 */
	readonly signed: boolean;

	/**
	 * Whether the response frame carries a message commitment.
	 */
	readonly messageIntegrity: boolean;

	/**
	 * Whether the response frame carries a frame witness.
	 */
	readonly frameIntegrity: boolean;
}

/**
 * The endpoint of one page round trip.
 */
export interface SessionOptions {
	/**
	 * The endpoint of the server that the page dials.
	 */
	readonly url: string;
}

/**
 * A session that pins the certificate of its server.
 */
export interface PinnedSessionOptions extends SessionOptions {
	/**
	 * The DER certificate of the server, in base64.
	 */
	readonly serverCertB64: string;
}

/**
 * A round trip of one opaque payload.
 */
export interface PayloadOptions extends SessionOptions {
	/**
	 * The payload of each frame, in hex.
	 */
	readonly payloadHex: string;
}

/**
 * A round trip of one opaque payload over a pinned session.
 */
export interface PinnedPayloadOptions extends PinnedSessionOptions, PayloadOptions {}

/**
 * The one opaque frame of a round trip.
 */
export interface EchoOptions extends PayloadOptions {
	/**
	 * The id of the frame, as text.
	 */
	readonly idText: string;

	/**
	 * The order of the frame.
	 */
	readonly order: number;
}

/**
 * The one opaque frame of a round trip over a pinned session.
 */
export interface PinnedEchoOptions extends EchoOptions, PinnedSessionOptions {}

/**
 * The one opaque frame of a round trip over a mutually authenticated session.
 */
export interface MutualEchoOptions extends PinnedEchoOptions {
	/**
	 * The DER certificate of the client, in base64.
	 */
	readonly clientCertB64: string;

	/**
	 * The raw signing key of the client, in base64.
	 */
	readonly clientKeyB64: string;
}

async function toResult(response: Frame): Promise<RoundTripResult> {
	const body = await response.open(ENGINE.opaque);
	return {
		bodyHex: bytesToHex(body),
		version: response.version,
		idText: TEXT.decode(response.id),
		order: response.order.toString(),
		signed: response.signed,
		messageIntegrity: response.messageIntegrity,
		frameIntegrity: response.frameIntegrity,
	};
}

/**
 * How a page dials the stack: each kind connects its own way.
 */
interface PageDial {
	/**
	 * Open a multiplexed client to `url` through `engine`.
	 */
	connect(engine: Engine, url: string): Promise<TightbeamWsClient>;
}

/**
 * A cleartext dial under the stream cap of the stack.
 */
class CleartextDial implements PageDial {
	readonly #facts: DialFacts;

	private constructor(facts: DialFacts) {
		this.#facts = facts;
	}

	/**
	 * The cleartext dial under the stream cap of `facts`.
	 */
	static of(facts: DialFacts): CleartextDial {
		const dial = new CleartextDial(facts);
		return dial;
	}

	connect(engine: Engine, url: string): Promise<TightbeamWsClient> {
		const cleartext = engine.connectCleartext(url, this.#facts.cleartext);
		return cleartext;
	}
}

/**
 * A server-authenticated dial, which pins the server certificate.
 */
class PinnedDial implements PageDial {
	readonly #serverCert: Uint8Array;

	private constructor(serverCert: Uint8Array) {
		this.#serverCert = serverCert;
	}

	/**
	 * The dial that pins the certificate `serverCertB64` encodes.
	 */
	static of(serverCertB64: string): PinnedDial {
		const dial = new PinnedDial(base64ToBytes(serverCertB64));
		return dial;
	}

	connect(engine: Engine, url: string): Promise<TightbeamWsClient> {
		const pinned = engine.connect(url, this.#serverCert);
		return pinned;
	}
}

/**
 * A mutually authenticated dial, which requests the ceiling of the paywall
 * and pays its invoice.
 */
class MutualDial implements PageDial {
	readonly #identity: MutualIdentity;

	readonly #paywall: StackPaywall;

	private constructor(identity: MutualIdentity, paywall: StackPaywall) {
		this.#identity = identity;
		this.#paywall = paywall;
	}

	/**
	 * The dial that presents `identity` under the paywall of `facts`.
	 */
	static of(identity: MutualIdentity, facts: DialFacts): MutualDial {
		const dial = new MutualDial(identity, facts.paywall);
		return dial;
	}

	connect(engine: Engine, url: string): Promise<TightbeamWsClient> {
		const options = this.#paywall.sessionOptions();
		const mutual = engine.connectMutual(url, this.#identity, options);
		return mutual;
	}
}

/**
 * Open a multiplexed client to `url` through `dial`, run `run`, and release
 * the socket on every exit.
 */
async function withMuxClient<T>(
	url: string,
	dial: PageDial,
	run: (client: TightbeamWsClient) => Promise<T>,
): Promise<T> {
	await using client = await dial.connect(ENGINE, url);
	const result = await run(client);
	return result;
}

/**
 * Emit the one opaque frame of `echo` over a client that `dial` opens, and
 * decode the echo.
 */
async function emitAndDecode(dial: PageDial, echo: EchoOptions): Promise<RoundTripResult> {
	const exchange = async (client: EmitClient): Promise<Frame> => {
		const built = await ENGINE.frameBuilder(hexToBytes(echo.payloadHex))
			.withId(echo.idText)
			.withOrder(echo.order)
			.build();

		const reply = await EchoDials.emitOrFail(client, built);
		return reply;
	};

	const response = await withMuxClient(echo.url, dial, exchange);
	const result = await toResult(response);
	return result;
}

/**
 * The echo of one opaque frame over a cleartext session.
 */
async function roundTrip(echo: EchoOptions): Promise<RoundTripResult> {
	const result = await emitAndDecode(CleartextDial.of(DIAL), echo);
	return result;
}

/**
 * The echo of one opaque frame over an encrypted session.
 */
async function secureRoundTrip(echo: PinnedEchoOptions): Promise<RoundTripResult> {
	const dial = PinnedDial.of(echo.serverCertB64);
	const result = await emitAndDecode(dial, echo);
	return result;
}

/**
 * The echo of one opaque frame over a mutually authenticated session.
 */
async function mutualRoundTrip(echo: MutualEchoOptions): Promise<RoundTripResult> {
	const identity = {
		serverCertDer: base64ToBytes(echo.serverCertB64),
		clientCertDer: base64ToBytes(echo.clientCertB64),
		clientKey: base64ToBytes(echo.clientKeyB64),
	};

	const dial = MutualDial.of(identity, DIAL);
	const result = await emitAndDecode(dial, echo);
	return result;
}

/**
 * The mutual round trip whose client key stays in an external signer. The
 * server pins the client certificate and settles the paywall, so a completed
 * round trip proves the handshake signed through the signer.
 */
async function mutualSignerRoundTrip(echo: MutualEchoOptions): Promise<RoundTripResult> {
	const clientKey = base64ToBytes(echo.clientKeyB64);
	const signer = new NobleTransportSigner(ENGINE, clientKey);
	const identity = {
		serverCertDer: base64ToBytes(echo.serverCertB64),
		clientCertDer: base64ToBytes(echo.clientCertB64),
		clientKey: signer,
	};

	const dial = MutualDial.of(identity, DIAL);
	const result = await emitAndDecode(dial, echo);
	return result;
}

/**
 * The outcome of a signed round-trip: what the frame reported plus the
 * verification verdicts recomputed on the echoed bytes.
 */
export interface SignedRoundTripResult extends RoundTripResult {
	/**
	 * Whether the signature of the echo verifies under the signing key.
	 */
	readonly signatureValid: boolean;

	/**
	 * The verdict of the frame witness of the echo.
	 */
	readonly frameVerdict: string;

	/**
	 * The verdict of the message commitment under the salt of the frame.
	 */
	readonly messageVerdict: string;

	/**
	 * The verdict of the message commitment under another salt.
	 */
	readonly wrongSaltVerdict: string;
}

/**
 * The one opaque frame of a signed, committed round trip.
 */
export interface SignedEchoOptions extends EchoOptions {
	/**
	 * The raw signing key of the frame, in hex.
	 */
	readonly signingKeyHex: string;

	/**
	 * The salt that hides the message commitment, in hex.
	 */
	readonly saltHex: string;
}

/**
 * The echo of one signed, committed frame over a cleartext session, with the
 * verdicts that the page recomputes on it.
 */
async function signedRoundTrip(echo: SignedEchoOptions): Promise<SignedRoundTripResult> {
	const signingKey = ENGINE.signingKey(hexToBytes(echo.signingKeyHex));
	const committed = ENGINE.salt(hexToBytes(echo.saltHex));
	const salt = ENGINE.salt(hexToBytes(echo.saltHex));
	const wrongSalt = ENGINE.salt(hexToBytes("deadbeef".repeat(4)));

	const dial = CleartextDial.of(DIAL);
	const response = await withMuxClient(echo.url, dial, async (client) => {
		const built = await ENGINE.frameBuilder(hexToBytes(echo.payloadHex))
			.withId(echo.idText)
			.withOrder(echo.order)
			.withMessageHasher(ENGINE.sha3_256, committed)
			.withWitnessHasher(ENGINE.sha3_256)
			.withSigner(signingKey)
			.build();

		const reply = await EchoDials.emitOrFail(client, built);
		return reply;
	});

	let signatureValid = false;
	try {
		await response.verify(signingKey.verifyingKey());
		signatureValid = true;
	} catch {
		signatureValid = false;
	}

	return {
		...(await toResult(response)),
		signatureValid,
		frameVerdict: await response.frameIntegrityVerdict(),
		messageVerdict: await response.messageCommitmentVerdict(salt),
		wrongSaltVerdict: await response.messageCommitmentVerdict(wrongSalt),
	};
}

/**
 * The outcome of an AEAD-sealed round-trip: the ciphertext markers plus the
 * plaintext recovered with the key.
 */
export interface SealedRoundTripResult {
	/**
	 * Whether the echo carries a sealed body.
	 */
	readonly confidential: boolean;

	/**
	 * The dotted OID of the cipher that sealed the body.
	 */
	readonly confidentialityOid: string;

	/**
	 * Whether the sealed body differs from the payload.
	 */
	readonly ciphertextDiffers: boolean;

	/**
	 * The body that the key opens, in hex.
	 */
	readonly decryptedHex: string;
}

/**
 * The echo of one AES-256-GCM sealed frame over a cleartext session.
 */
async function sealedRoundTrip(echo: EchoOptions): Promise<SealedRoundTripResult> {
	const payload = hexToBytes(echo.payloadHex);
	const cipher = ENGINE.aes256Gcm(SEAL_SECRET);

	const dial = CleartextDial.of(DIAL);
	const response = await withMuxClient(echo.url, dial, async (client) => {
		const built = await ENGINE.frameBuilder(payload)
			.withId(echo.idText)
			.withOrder(echo.order)
			.withEncryptor(cipher)
			.build();

		const reply = await EchoDials.emitOrFail(client, built);
		return reply;
	});

	const algorithm = response.confidentialityInfo?.algorithmOid;
	const decrypted = await response.open(ENGINE.opaque, { opener: cipher });
	return {
		confidential: response.confidential,
		confidentialityOid: algorithm?.toString() ?? "",
		ciphertextDiffers: bytesToHex(response.bodyDer) !== echo.payloadHex,
		decryptedHex: bytesToHex(decrypted),
	};
}

/**
 * The outcome of a compressed round-trip: the compactness markers plus the
 * body recovered with the profile zstd inflator.
 */
export interface CompressedRoundTripResult {
	/**
	 * Whether the echo carries a compressed body.
	 */
	readonly compressed: boolean;

	/**
	 * The dotted OID of the compression of the body.
	 */
	readonly compactnessOid: string;

	/**
	 * The body that the inflator recovers, in hex.
	 */
	readonly inflatedHex: string;
}

/**
 * The echo of one zstd-compressed frame over a cleartext session.
 */
async function compressedRoundTrip(echo: EchoOptions): Promise<CompressedRoundTripResult> {
	const zstd = ENGINE.zstd();

	const dial = CleartextDial.of(DIAL);
	const response = await withMuxClient(echo.url, dial, async (client) => {
		const built = await ENGINE.frameBuilder(hexToBytes(echo.payloadHex))
			.withId(echo.idText)
			.withOrder(echo.order)
			.withCompressor(zstd)
			.build();

		const reply = await EchoDials.emitOrFail(client, built);
		return reply;
	});

	const inflated = await response.open(ENGINE.opaque, { inflator: zstd });
	return {
		compressed: response.compressed,
		compactnessOid: response.compactnessInfo?.algorithmOid.toString() ?? "",
		inflatedHex: bytesToHex(inflated),
	};
}

/**
 * The echo of one compressed, then sealed, frame over a cleartext session.
 */
async function compressedSealedRoundTrip(echo: EchoOptions): Promise<CompressedRoundTripResult> {
	const zstd = ENGINE.zstd();
	const cipher = ENGINE.aes256Gcm(SEAL_SECRET);

	const dial = CleartextDial.of(DIAL);
	const response = await withMuxClient(echo.url, dial, async (client) => {
		const built = await ENGINE.frameBuilder(hexToBytes(echo.payloadHex))
			.withId(echo.idText)
			.withOrder(echo.order)
			.withCompressor(zstd)
			.withEncryptor(cipher)
			.build();

		const reply = await EchoDials.emitOrFail(client, built);
		return reply;
	});

	const inflated = await response.open(ENGINE.opaque, {
		opener: cipher,
		inflator: zstd,
	});
	return {
		compressed: response.compressed,
		compactnessOid: response.compactnessInfo?.algorithmOid.toString() ?? "",
		inflatedHex: bytesToHex(inflated),
	};
}

/**
 * A note round-tripped as a typed body: JSON under a wrapped payload codec,
 * decoded and runtime-validated in the browser.
 */
export type TypedRoundTripResult = Note;

/**
 * The one typed frame of a round trip.
 */
export interface TypedEchoOptions extends SessionOptions {
	/**
	 * The id of the frame, as text.
	 */
	readonly idText: string;

	/**
	 * The order of the frame.
	 */
	readonly order: number;

	/**
	 * The note that the frame carries.
	 */
	readonly note: Note;
}

/**
 * The echo of one note under a wrapped payload codec over a cleartext
 * session.
 */
async function typedRoundTrip(echo: TypedEchoOptions): Promise<TypedRoundTripResult> {
	const dial = CleartextDial.of(DIAL);
	const response = await withMuxClient(echo.url, dial, async (client) => {
		const built = await ENGINE.messageBuilder(NOTES, echo.note).withId(echo.idText).withOrder(echo.order).build();

		const reply = await EchoDials.emitOrFail(client, built);
		return reply;
	});

	const message = await response.open(NOTES);
	return message;
}

/**
 * The outcome of concurrent emits on one multiplexed session: the echoed
 * ids and bodies in emit order, proving per-stream correlation.
 */
export interface MuxConcurrentResult {
	/**
	 * The ids of the echoes, in emit order.
	 */
	readonly echoedIds: string[];

	/**
	 * The opened bodies of the echoes, in hex, in emit order.
	 */
	readonly echoedBodiesHex: string[];
}

/**
 * `payload` suffixed with the emit index, so each concurrent response names the emit it answers.
 */
function indexedBody(payload: Uint8Array, index: number): Uint8Array {
	const body = new Uint8Array(payload.length + 1);
	body.set(payload);
	body[payload.length] = index;
	return body;
}

/**
 * Emit three indexed frames of `options` concurrently on one session that
 * `dial` opens.
 */
async function concurrentRoundTrip(dial: PageDial, options: PayloadOptions): Promise<MuxConcurrentResult> {
	const payload = hexToBytes(options.payloadHex);
	const labels = ["mux-browser-1", "mux-browser-2", "mux-browser-3"];

	const result = await withMuxClient(options.url, dial, async (client) => {
		const emits = labels.map(async (label, index) => {
			const built = await ENGINE.frameBuilder(indexedBody(payload, index))
				.withId(label)
				.withOrder(index + 1)
				.build();

			const response = await EchoDials.emitOrFail(client, built);
			return response;
		});

		const echoed = await Promise.all(emits);
		const bodies = await Promise.all(echoed.map((response) => response.open(ENGINE.opaque)));

		const result = {
			echoedIds: echoed.map((response) => TEXT.decode(response.id)),
			echoedBodiesHex: bodies.map((body) => bytesToHex(body)),
		};
		return result;
	});
	return result;
}

/**
 * The concurrent round-trip over the encrypted mux lane, pinned to the
 * server certificate.
 */
async function muxConcurrentRoundTrip(options: PinnedPayloadOptions): Promise<MuxConcurrentResult> {
	const dial = PinnedDial.of(options.serverCertB64);
	const result = await concurrentRoundTrip(dial, options);
	return result;
}

/**
 * The outcome of a server-initiated stream: the request ids the in-page
 * handler served plus the reply the server relayed back on the original
 * stream.
 */
export interface MuxCallbackResult {
	/**
	 * The ids of the requests that the page handler served.
	 */
	readonly servedIds: string[];

	/**
	 * The id of the reply that the server relayed, as text.
	 */
	readonly relayedIdText: string;

	/**
	 * The opened body of the relayed reply, in hex.
	 */
	readonly relayedBodyHex: string;
}

/**
 * A call-back round trip: the trigger payload, and the reply that the page
 * handler answers the call-back with.
 */
export interface CallbackOptions extends PinnedPayloadOptions {
	/**
	 * The body of the reply of the page handler, in hex.
	 */
	readonly replyHex: string;
}

/**
 * The call-back round trip, whose server-initiated stream the page handler
 * answers.
 */
async function muxCallbackRoundTrip(options: CallbackOptions): Promise<MuxCallbackResult> {
	const dial = PinnedDial.of(options.serverCertB64);
	const result = await withMuxClient(options.url, dial, async (client) => {
		const servedIds: string[] = [];
		client.serve(async (request) => {
			servedIds.push(TEXT.decode(request.id));

			const reply = await ENGINE.frameBuilder(hexToBytes(options.replyHex))
				.withId("browser-reply")
				.withOrder(9)
				.build();
			return reply;
		});

		/*
		 * The `call-me` id makes the server open its own stream back to
		 * this page. The handler's reply follows the original stream.
		 */
		const callMe = await ENGINE.frameBuilder(hexToBytes(options.payloadHex))
			.withId("call-me-browser")
			.withOrder(4)
			.build();

		const relayed = await EchoDials.emitOrFail(client, callMe);
		const body = await relayed.open(ENGINE.opaque);
		const result = {
			servedIds,
			relayedIdText: TEXT.decode(relayed.id),
			relayedBodyHex: bytesToHex(body),
		};
		return result;
	});
	return result;
}

/**
 * The lifecycle surface observed on one multiplexed session: liveness
 * probes while healthy (`ping` and `waitForStreamSlot` must resolve for
 * this to return at all), then the drain markers after a local
 * `shutdownWith`.
 */
export interface MuxLifecycleResult {
	/**
	 * Whether the healthy session had a free stream slot.
	 */
	readonly headroom: boolean;

	/**
	 * Whether the healthy session held no pending stream.
	 */
	readonly pendingIdle: boolean;

	/**
	 * Whether the healthy session held no GoAway reason.
	 */
	readonly liveReasonEmpty: boolean;

	/**
	 * The message of the rejection of a ping whose signal was aborted.
	 */
	readonly abandonedPingRejection: string;

	/**
	 * The code of the refusal of an emit after the local drain.
	 */
	readonly drainCode: string;

	/**
	 * Whether the locally drained session held no GoAway reason.
	 */
	readonly localReasonEmpty: boolean;
}

/**
 * The lifecycle probe of one pinned session, whose drain the page starts.
 */
async function muxLifecycleProbe(options: PinnedSessionOptions): Promise<MuxLifecycleResult> {
	const dial = PinnedDial.of(options.serverCertB64);
	const result = await withMuxClient(options.url, dial, async (client) => {
		await client.ping();
		await client.waitForStreamSlot();

		const headroom = client.hasStreamHeadroom;
		const pendingIdle = !client.hasPendingStreams;
		const liveReasonEmpty = client.goawayReason === undefined;

		const abandoned = new AbortController();
		abandoned.abort(new Error("ping abandoned"));

		let abandonedPingRejection = "";
		try {
			await client.ping({ signal: abandoned.signal });
		} catch (error) {
			if (error instanceof Error) {
				abandonedPingRejection = error.message;
			}
		}

		await client.shutdownWith("enhance-your-calm");

		let drainCode = "";
		try {
			const after = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x1f]))
				.withId("browser-after-calm")
				.withOrder(1)
				.build();
			await client.emit(after);
		} catch (error) {
			if (ENGINE.isTransportError(error)) {
				drainCode = error.code;
			}
		}

		const localReasonEmpty = client.goawayReason === undefined;
		const result = {
			headroom,
			pendingIdle,
			liveReasonEmpty,
			abandonedPingRejection,
			drainCode,
			localReasonEmpty,
		};
		return result;
	});
	return result;
}

/**
 * The markers left by a peer-initiated drain: the code the stream slot wait
 * refused with once the GoAway landed, the GoAway reason the client recorded,
 * and how the never-answered emit settled.
 */
export interface MuxDrainResult {
	/**
	 * The code that the parked stream slot wait refused with.
	 */
	readonly slotCode: string;

	/**
	 * The GoAway reason that the client recorded.
	 */
	readonly reason: string;

	/**
	 * The message of the rejection of the emit that the server never answered.
	 */
	readonly emitRejection: string;
}

/**
 * The drain that the server starts on one pinned session, as the page reads
 * it.
 */
async function muxDrainReason(options: PinnedSessionOptions): Promise<MuxDrainResult> {
	const dial = PinnedDial.of(options.serverCertB64);
	const result = await withMuxClient(options.url, dial, async (client) => {
		/*
		 * Parked call-backs hold every slot but the one that the `drain-calm`
		 * id takes, and its EnhanceYourCalm GoAway wakes the parked slot wait
		 * with `Draining`.
		 */
		client.serve(() => new Promise(() => undefined));

		const holds = await Promise.all(
			Array.from({ length: client.maxConcurrentStreams - 1 }, (_, index) =>
				ENGINE.frameBuilder(new Uint8Array([0xb0, 0x1e]))
					.withId(`call-me-hold-browser-${index}`)
					.withOrder(index + 1)
					.build(),
			),
		);
		const drain = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x1d]))
			.withId("drain-calm-browser")
			.withOrder(1)
			.build();

		const controller = new AbortController();
		const signal = controller.signal;
		const held = holds.map((frame) => client.emit(frame, { signal }).catch((error: unknown) => error));

		const pending = client.emit(drain, { signal });

		let slotCode = "";
		try {
			await client.waitForStreamSlot();
		} catch (error) {
			if (ENGINE.isTransportError(error)) {
				slotCode = error.code;
			}
		}

		controller.abort(new Error("drain observed"));

		let emitRejection = "";
		try {
			await pending;
		} catch (error) {
			if (error instanceof Error) {
				emitRejection = error.message;
			}
		}

		await Promise.all(held);
		const result = {
			slotCode,
			reason: client.goawayReason ?? "",
			emitRejection,
		};
		return result;
	});
	return result;
}

/**
 * The parked variant of the call-back exchange: the trigger goes out
 * before any handler registers, proving early server streams wait for
 * `serve` instead of being dropped.
 */
async function muxParkedCallbackRoundTrip(options: CallbackOptions): Promise<MuxCallbackResult> {
	const dial = PinnedDial.of(options.serverCertB64);
	const result = await withMuxClient(options.url, dial, async (client) => {
		const callMe = await ENGINE.frameBuilder(hexToBytes(options.payloadHex))
			.withId("call-me-parked-browser")
			.withOrder(4)
			.build();

		/*
		 * The emit takes its stream slot before it returns, so the request
		 * left the client before serve registers.
		 */
		const pending = EchoDials.emitOrFail(client, callMe);
		if (!client.hasPendingStreams) {
			throw new Error("the call-back emit holds no stream slot");
		}

		const servedIds: string[] = [];
		client.serve(async (request) => {
			servedIds.push(TEXT.decode(request.id));

			const reply = await ENGINE.frameBuilder(hexToBytes(options.replyHex))
				.withId("late-browser-reply")
				.withOrder(9)
				.build();
			return reply;
		});

		const relayed = await pending;
		const body = await relayed.open(ENGINE.opaque);
		const result = {
			servedIds,
			relayedIdText: TEXT.decode(relayed.id),
			relayedBodyHex: bytesToHex(body),
		};
		return result;
	});
	return result;
}

/**
 * How the caller observed a handler's `StreamRefusal`: the structured
 * rejection's name and its relayed gRPC status code.
 */
export interface MuxRefusalResult {
	/**
	 * The name of the error that the emit rejected with.
	 */
	readonly rejectionName: string;

	/**
	 * The code of the error that the emit rejected with.
	 */
	readonly rejectionCode: string;
}

/**
 * The refusal relay: the page handler refuses the server's call-back
 * stream with a chosen gRPC status, and the echo server relays that
 * failure as the answer on the original stream.
 */
async function muxRefusalRoundTrip(options: PinnedPayloadOptions): Promise<MuxRefusalResult> {
	const dial = PinnedDial.of(options.serverCertB64);
	const result = await withMuxClient(options.url, dial, async (client) => {
		client.serve(() => {
			throw new StreamRefusal("NotFound", "nothing here");
		});

		const callMe = await ENGINE.frameBuilder(hexToBytes(options.payloadHex))
			.withId("call-me-refused-browser")
			.withOrder(4)
			.build();

		try {
			await EchoDials.emitOrFail(client, callMe);
		} catch (error) {
			if (ENGINE.isTransportError(error)) {
				return { rejectionName: error.name, rejectionCode: error.code };
			}

			return { rejectionName: String(error), rejectionCode: "" };
		}

		return { rejectionName: "", rejectionCode: "" };
	});
	return result;
}

/**
 * The outcome of a work submission through the cluster gateway: the
 * servlet's typed echo plus the response-signature verdict recomputed
 * in the browser.
 */
export interface WorkRoundTripResult {
	/**
	 * The opened body of the answer of the servlet, as text.
	 */
	readonly bodyText: string;

	/**
	 * The id of the answer, as text.
	 */
	readonly idText: string;

	/**
	 * Whether the signature of the answer verifies under the work key.
	 */
	readonly signatureValid: boolean;
}

/**
 * How the caller observed a gateway work refusal: the structured
 * rejection's name, its `code`, and the transit status it carried.
 */
export interface WorkRefusalResult {
	/**
	 * The name of the error that the submission rejected with.
	 */
	readonly rejectionName: string;

	/**
	 * The code of the error that the submission rejected with.
	 */
	readonly rejectionCode: string;

	/**
	 * The transit status that the refusal carried.
	 */
	readonly rejectionStatus: string;
}

/**
 * A work submission through the cluster gateway.
 */
export interface WorkRefusalOptions extends PinnedPayloadOptions {
	/**
	 * The servlet type that the work names.
	 */
	readonly target: string;

	/**
	 * The raw end-to-end work signing key, in base64.
	 */
	readonly workKeyB64: string;
}

/**
 * A work submission whose answer the page verifies.
 */
export interface WorkRoundTripOptions extends WorkRefusalOptions {
	/**
	 * The id of the work frame, as text.
	 */
	readonly idText: string;

	/**
	 * The order of the work frame.
	 */
	readonly order: number;
}

/**
 * The end-to-end work frame of `work`, signed by `workKey`, which the gateway
 * MUST forward to the servlet unchanged.
 */
async function signedWorkFrame(work: WorkRoundTripOptions, workKey: Secp256k1SigningKey): Promise<Frame> {
	const built = await ENGINE.frameBuilder(hexToBytes(work.payloadHex))
		.withId(work.idText)
		.withOrder(work.order)
		.withSigner(workKey)
		.build();
	return built;
}

/**
 * The submission of one signed work frame, whose answer the page verifies.
 */
async function workRoundTrip(options: WorkRoundTripOptions): Promise<WorkRoundTripResult> {
	const workKey = ENGINE.signingKey(base64ToBytes(options.workKeyB64));

	const dial = PinnedDial.of(options.serverCertB64);
	const result = await withMuxClient(options.url, dial, async (client) => {
		const built = await signedWorkFrame(options, workKey);
		const response = await client.submitWork(options.target, built);

		let signatureValid = false;
		try {
			await response.verify(workKey.verifyingKey());
			signatureValid = true;
		} catch {
			signatureValid = false;
		}

		const body = await response.open(ENGINE.opaque);
		return {
			bodyText: TEXT.decode(body),
			idText: TEXT.decode(response.id),
			signatureValid,
		};
	});
	return result;
}

/**
 * The submission of one signed work frame that the gateway refuses.
 */
async function workRefusal(options: WorkRefusalOptions): Promise<WorkRefusalResult> {
	const workKey = ENGINE.signingKey(base64ToBytes(options.workKeyB64));
	const work = { ...options, idText: "e2e-work-refused", order: 1 };

	const dial = PinnedDial.of(options.serverCertB64);
	const result = await withMuxClient(options.url, dial, async (client) => {
		const built = await signedWorkFrame(work, workKey);

		try {
			await client.submitWork(options.target, built);
		} catch (error) {
			if (ENGINE.isTransportError(error)) {
				let rejectionStatus = "";
				if (error.code === "WorkRefused") {
					rejectionStatus = error.status;
				}

				return {
					rejectionName: error.name,
					rejectionCode: error.code,
					rejectionStatus,
				};
			}

			return {
				rejectionName: String(error),
				rejectionCode: "",
				rejectionStatus: "",
			};
		}

		return { rejectionName: "", rejectionCode: "", rejectionStatus: "" };
	});
	return result;
}

/**
 * The concurrent round-trip over the cleartext mux lane: no certificate,
 * symmetric stream cap in place of negotiation.
 */
async function muxClearConcurrentRoundTrip(options: PayloadOptions): Promise<MuxConcurrentResult> {
	const dial = CleartextDial.of(DIAL);
	const result = await concurrentRoundTrip(dial, options);
	return result;
}

/**
 * The one frame of a progressive round trip over a pinned session.
 */
export interface StreamingOptions extends PinnedPayloadOptions {
	/**
	 * The id of the frame, as text.
	 */
	readonly idText: string;
}

/**
 * The echo of one frame whose DER the page pushes as a progressive body in
 * two chunks.
 */
async function streamingRoundTrip(options: StreamingOptions): Promise<RoundTripResult> {
	const dial = PinnedDial.of(options.serverCertB64);
	const result = await withMuxClient(options.url, dial, async (client) => {
		const built = await ENGINE.frameBuilder(hexToBytes(options.payloadHex))
			.withId(options.idText)
			.withOrder(1)
			.build();

		const der = built.toDer();
		const mid = Math.floor(der.length / 2);

		const stream = client.openStream();
		await stream.push(der.subarray(0, mid));
		await stream.push(der.subarray(mid));

		const response = await stream.close();
		if (response === undefined) {
			throw new Error("streaming peer returned no response frame");
		}

		const outcome = await toResult(response);
		return outcome;
	});
	return result;
}

/**
 * Every round trip of the page, which the specs reach as `window.tb`.
 */
const api = {
	roundTrip,
	secureRoundTrip,
	mutualRoundTrip,
	mutualSignerRoundTrip,
	signedRoundTrip,
	sealedRoundTrip,
	compressedRoundTrip,
	compressedSealedRoundTrip,
	typedRoundTrip,
	muxConcurrentRoundTrip,
	muxCallbackRoundTrip,
	muxClearConcurrentRoundTrip,
	muxLifecycleProbe,
	muxDrainReason,
	streamingRoundTrip,
	muxParkedCallbackRoundTrip,
	muxRefusalRoundTrip,
	workRoundTrip,
	workRefusal,
} as const;

/**
 * The round trips of the page, as `window.tb` holds them.
 */
export type PageApi = typeof api;

window.tb = api;

const status = document.querySelector("#status");
if (status) {
	status.textContent = "client ready";
}
