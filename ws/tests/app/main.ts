/**
 * Minimal, headless example app for the generic tightbeam-ws client.
 *
 * Builds frames with the fluent builder of its engine, ships them over the
 * socket, and surfaces the decoded response so the Playwright spec can assert
 * the body and metadata survived the round-trip.
 *
 * The query string carries the dial facts of the stack under their own
 * names, which {@link readDialFacts} parses once at load. The page loads the
 * engine once, before it reports ready.
 */

import type {
	Frame,
	MutualIdentity,
	Secp256k1SigningKey,
} from "@wahidgroup/tightbeam-ws-client";
import {
	StreamRefusal,
	TightbeamWsClient,
} from "@wahidgroup/tightbeam-ws-client";

import type { EmitClient, Note } from "../fixtures.js";
import {
	NotePayload,
	SEAL_SECRET,
	base64ToBytes,
	bytesToHex,
	emitOrFail,
	hexToBytes,
	mutualSessionOptions,
	queryFacts,
	readDialFacts,
	withClient,
} from "../fixtures.js";
import { NobleTransportSigner } from "../signer.js";

const TEXT = new TextDecoder();

/**
 * The stack facts in the query string that the spec opened the page with.
 */
const PAGE_FACTS = queryFacts(window.location.search);

/**
 * The stream cap and the demo paywall of the stack.
 */
const DIAL = readDialFacts(PAGE_FACTS);

/**
 * The engine every round-trip of the page builds, parses, and dials with.
 */
const ENGINE = await TightbeamWsClient.init();

/**
 * The typed body codec for a note: JSON in the profile opaque wrapper.
 */
const NOTES = ENGINE.wrapping(NotePayload);

/**
 * The decoded outcome of a single round-trip, in a structured-clone-safe shape
 * (no `bigint`) so it crosses the Playwright `page.evaluate` boundary.
 */
export interface RoundTripResult {
	readonly bodyHex: string;
	readonly version: number;
	readonly idText: string;
	readonly order: string;
	readonly signed: boolean;
	readonly messageIntegrity: boolean;
	readonly frameIntegrity: boolean;
}

function toResult(response: Frame): RoundTripResult {
	return {
		bodyHex: bytesToHex(response.message(ENGINE.opaque)),
		version: response.version,
		idText: TEXT.decode(response.id),
		order: response.order.toString(),
		signed: response.signed,
		messageIntegrity: response.messageIntegrity,
		frameIntegrity: response.frameIntegrity,
	};
}

/**
 * How a page dials the stack: in cleartext when absent, pinning a base64
 * server certificate, or presenting a mutual identity as well.
 */
type PageCredentials = string | MutualIdentity | undefined;

/**
 * The one opaque frame a round-trip emits.
 */
interface EchoFields {
	readonly payloadHex: string;
	readonly idText: string;
	readonly order: number;
}

/**
 * Dial `url` with `credentials`. A cleartext dial passes the stream cap of
 * the stack, and a mutual dial requests the ceiling of its paywall and pays
 * its invoice.
 */
function dial(
	url: string,
	credentials: PageCredentials,
): Promise<TightbeamWsClient> {
	if (credentials === undefined) {
		const options = { streams: DIAL.streams };
		const cleartext = ENGINE.connectCleartext(url, options);
		return cleartext;
	}
	if (typeof credentials === "string") {
		const serverCert = base64ToBytes(credentials);
		const pinned = ENGINE.connect(url, serverCert);
		return pinned;
	}

	const options = mutualSessionOptions(DIAL.paywall);
	const mutual = ENGINE.connectMutual(url, credentials, options);
	return mutual;
}

/**
 * Open a multiplexed client to `url` under `credentials`, run the exchange
 * body, and always release the socket.
 */
async function withMuxClient<T>(
	url: string,
	credentials: PageCredentials,
	run: (client: TightbeamWsClient) => Promise<T>,
): Promise<T> {
	const connect = (): Promise<TightbeamWsClient> => dial(url, credentials);

	const result = await withClient(connect, run);
	return result;
}

/**
 * Open a client to `url` under `credentials`, emit the one opaque frame
 * `echo` names, release the socket, and decode the echo.
 */
async function emitAndDecode(
	url: string,
	credentials: PageCredentials,
	echo: EchoFields,
): Promise<RoundTripResult> {
	const exchange = async (client: EmitClient): Promise<Frame> => {
		const built = await ENGINE.frameBuilder(hexToBytes(echo.payloadHex))
			.withId(echo.idText)
			.withOrder(echo.order)
			.build();

		const reply = await emitOrFail(client, built);
		return reply;
	};

	const response = await withMuxClient(url, credentials, exchange);
	const result = toResult(response);
	return result;
}

export async function roundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<RoundTripResult> {
	const echo = { payloadHex, idText, order };

	const result = await emitAndDecode(url, undefined, echo);
	return result;
}

export async function secureRoundTrip(
	url: string,
	serverCertB64: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<RoundTripResult> {
	const echo = { payloadHex, idText, order };

	const result = await emitAndDecode(url, serverCertB64, echo);
	return result;
}

export async function mutualRoundTrip(
	url: string,
	serverCertB64: string,
	clientCertB64: string,
	clientKeyB64: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<RoundTripResult> {
	const identity = {
		serverCertDer: base64ToBytes(serverCertB64),
		clientCertDer: base64ToBytes(clientCertB64),
		clientKey: base64ToBytes(clientKeyB64),
	};

	const echo = { payloadHex, idText, order };
	const result = await emitAndDecode(url, identity, echo);
	return result;
}

/**
 * The mutual round-trip outcome plus how many prehashes the external
 * signer answered, proving the handshake used it.
 */
export interface SignerRoundTripResult extends RoundTripResult {
	readonly signatures: number;
}

export async function mutualSignerRoundTrip(
	url: string,
	serverCertB64: string,
	clientCertB64: string,
	clientKeyB64: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<SignerRoundTripResult> {
	const clientKey = base64ToBytes(clientKeyB64);
	const signer = new NobleTransportSigner(ENGINE, clientKey);
	const identity = {
		serverCertDer: base64ToBytes(serverCertB64),
		clientCertDer: base64ToBytes(clientCertB64),
		clientKey: signer,
	};

	const echo = { payloadHex, idText, order };

	const decoded = await emitAndDecode(url, identity, echo);
	const result = { ...decoded, signatures: signer.signatures };
	return result;
}

/**
 * The outcome of a signed round-trip: what the frame reported plus the
 * verification verdicts recomputed on the echoed bytes.
 */
export interface SignedRoundTripResult extends RoundTripResult {
	readonly signatureValid: boolean;
	readonly frameVerdict: string;
	readonly messageVerdict: string;
	readonly wrongSaltVerdict: string;
}

export async function signedRoundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
	signingKeyHex: string,
	saltHex: string,
): Promise<SignedRoundTripResult> {
	const signingKey = ENGINE.signingKey(hexToBytes(signingKeyHex));
	const committed = ENGINE.salt(hexToBytes(saltHex));
	const salt = ENGINE.salt(hexToBytes(saltHex));
	const wrongSalt = ENGINE.salt(hexToBytes("deadbeef".repeat(4)));

	const response = await withMuxClient(url, undefined, async (client) => {
		const built = await ENGINE.frameBuilder(hexToBytes(payloadHex))
			.withId(idText)
			.withOrder(order)
			.withMessageHasher(ENGINE.sha3_256)
			.withCommitment(committed)
			.withWitnessHasher(ENGINE.sha3_256)
			.withSigner(signingKey)
			.build();

		const reply = await emitOrFail(client, built);
		return reply;
	});

	let signatureValid = false;
	try {
		response.verify(signingKey.verifyingKey());
		signatureValid = true;
	} catch {
		signatureValid = false;
	}

	return {
		...toResult(response),
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
	readonly confidential: boolean;
	readonly confidentialityOid: string;
	readonly ciphertextDiffers: boolean;
	readonly decryptedHex: string;
}

export async function sealedRoundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<SealedRoundTripResult> {
	const payload = hexToBytes(payloadHex);
	const cipher = ENGINE.aes256Gcm(SEAL_SECRET);

	const response = await withMuxClient(url, undefined, async (client) => {
		const built = await ENGINE.frameBuilder(payload)
			.withId(idText)
			.withOrder(order)
			.withEncryptor(cipher)
			.build();

		const reply = await emitOrFail(client, built);
		return reply;
	});

	const algorithm = response.confidentialityInfo?.algorithmOid;
	const decrypted = await response.decryptMessage(cipher, ENGINE.opaque);
	return {
		confidential: response.confidential,
		confidentialityOid: algorithm?.toString() ?? "",
		ciphertextDiffers: bytesToHex(response.bodyDer) !== payloadHex,
		decryptedHex: bytesToHex(decrypted),
	};
}

/**
 * The outcome of a compressed round-trip: the compactness markers plus the
 * body recovered with the profile zstd inflator.
 */
export interface CompressedRoundTripResult {
	readonly compressed: boolean;
	readonly compactnessOid: string;
	readonly inflatedHex: string;
}

export async function compressedRoundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<CompressedRoundTripResult> {
	const zstd = ENGINE.zstd();

	const response = await withMuxClient(url, undefined, async (client) => {
		const built = await ENGINE.frameBuilder(hexToBytes(payloadHex))
			.withId(idText)
			.withOrder(order)
			.withCompressor(zstd)
			.build();

		const reply = await emitOrFail(client, built);
		return reply;
	});

	const inflated = await response.inflateMessage(zstd, ENGINE.opaque);
	return {
		compressed: response.compressed,
		compactnessOid: response.compactnessInfo?.algorithmOid.toString() ?? "",
		inflatedHex: bytesToHex(inflated),
	};
}

export async function compressedSealedRoundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<CompressedRoundTripResult> {
	const zstd = ENGINE.zstd();
	const cipher = ENGINE.aes256Gcm(SEAL_SECRET);

	const response = await withMuxClient(url, undefined, async (client) => {
		const built = await ENGINE.frameBuilder(hexToBytes(payloadHex))
			.withId(idText)
			.withOrder(order)
			.withCompressor(zstd)
			.withEncryptor(cipher)
			.build();

		const reply = await emitOrFail(client, built);
		return reply;
	});

	const inflated = await response.decryptMessage(cipher, ENGINE.opaque, zstd);
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

export async function typedRoundTrip(
	url: string,
	idText: string,
	order: number,
	author: string,
	text: string,
): Promise<TypedRoundTripResult> {
	const response = await withMuxClient(url, undefined, async (client) => {
		const built = await ENGINE.frameBuilder()
			.withId(idText)
			.withOrder(order)
			.withMessage(NOTES, { author, text })
			.build();

		const reply = await emitOrFail(client, built);
		return reply;
	});

	const message = response.message(NOTES);
	return message;
}

/**
 * The outcome of concurrent emits on one multiplexed session: the echoed
 * ids and bodies in emit order, proving per-stream correlation.
 */
export interface MuxConcurrentResult {
	readonly echoedIds: string[];
	readonly echoedBodiesHex: string[];
}

/**
 * `payload` suffixed with the emit index so concurrent responses cannot be
 * confused with each other.
 */
function indexedBody(payload: Uint8Array, index: number): Uint8Array {
	const body = new Uint8Array(payload.length + 1);
	body.set(payload);
	body[payload.length] = index;
	return body;
}

export async function muxConcurrentRoundTrip(
	url: string,
	serverCertB64: string | undefined,
	payloadHex: string,
): Promise<MuxConcurrentResult> {
	const payload = hexToBytes(payloadHex);
	const labels = ["mux-browser-1", "mux-browser-2", "mux-browser-3"];

	const result = await withMuxClient(url, serverCertB64, async (client) => {
		const emits = labels.map(async (label, index) => {
			const built = await ENGINE.frameBuilder(indexedBody(payload, index))
				.withId(label)
				.withOrder(index + 1)
				.build();

			const response = await emitOrFail(client, built);
			return response;
		});

		const echoed = await Promise.all(emits);
		const result = {
			echoedIds: echoed.map((response) => TEXT.decode(response.id)),
			echoedBodiesHex: echoed.map((response) =>
				bytesToHex(response.message(ENGINE.opaque)),
			),
		};
		return result;
	});
	return result;
}

/**
 * The outcome of a server-initiated stream: the request ids the in-page
 * handler served plus the reply the server relayed back on the original
 * stream.
 */
export interface MuxCallbackResult {
	readonly servedIds: string[];
	readonly relayedIdText: string;
	readonly relayedBodyHex: string;
}

export async function muxCallbackRoundTrip(
	url: string,
	serverCertB64: string,
	payloadHex: string,
	replyHex: string,
): Promise<MuxCallbackResult> {
	const result = await withMuxClient(url, serverCertB64, async (client) => {
		const servedIds: string[] = [];
		client.serve(async (request) => {
			servedIds.push(TEXT.decode(request.id));

			const reply = await ENGINE.frameBuilder(hexToBytes(replyHex))
				.withId("browser-reply")
				.withOrder(9)
				.build();
			return reply;
		});

		/*
		 * The `call-me` id makes the server open its own stream back to
		 * this page. The handler's reply follows the original stream.
		 */
		const callMe = await ENGINE.frameBuilder(hexToBytes(payloadHex))
			.withId("call-me-browser")
			.withOrder(4)
			.build();

		const relayed = await emitOrFail(client, callMe);
		const result = {
			servedIds,
			relayedIdText: TEXT.decode(relayed.id),
			relayedBodyHex: bytesToHex(relayed.message(ENGINE.opaque)),
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
	readonly headroom: boolean;
	readonly pendingIdle: boolean;
	readonly liveReasonEmpty: boolean;
	readonly abandonedPingRejection: string;
	readonly drainCode: string;
	readonly localReasonEmpty: boolean;
}

export async function muxLifecycleProbe(
	url: string,
	serverCertB64: string,
): Promise<MuxLifecycleResult> {
	const result = await withMuxClient(url, serverCertB64, async (client) => {
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
			const after = await ENGINE.frameBuilder(
				new Uint8Array([0xb0, 0x1f]),
			)
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
 * The markers left by a peer-initiated drain: the GoAway reason and code
 * the client recorded, plus how the never-answered emit settled.
 */
export interface MuxDrainResult {
	readonly reason: string;
	readonly code: number;
	readonly emitRejection: string;
}

export async function muxDrainReason(
	url: string,
	serverCertB64: string,
): Promise<MuxDrainResult> {
	const result = await withMuxClient(url, serverCertB64, async (client) => {
		/*
		 * The `drain-calm` id makes the server drain the session with an
		 * EnhanceYourCalm GoAway instead of echoing. The drain stops the
		 * server's writer before the response, so the emit never settles
		 * on its own and is aborted once the reason surfaces.
		 */
		const drain = await ENGINE.frameBuilder(new Uint8Array([0xb0, 0x1d]))
			.withId("drain-calm-browser")
			.withOrder(1)
			.build();

		const controller = new AbortController();
		const pending = client.emit(drain, { signal: controller.signal });

		// The Playwright test timeout bounds this poll.
		while (client.goawayReason === undefined) {
			await new Promise((resolve) => setTimeout(resolve, 25));
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

		const result = {
			reason: client.goawayReason ?? "",
			code: client.goawayCode ?? -1,
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
export async function muxParkedCallbackRoundTrip(
	url: string,
	serverCertB64: string,
	payloadHex: string,
	replyHex: string,
): Promise<MuxCallbackResult> {
	const result = await withMuxClient(url, serverCertB64, async (client) => {
		/*
		 * Fire the call-back with no handler, then wait until the local
		 * emit occupies a stream slot so serve registers only after the
		 * request left the client.
		 */
		const callMe = await ENGINE.frameBuilder(hexToBytes(payloadHex))
			.withId("call-me-parked-browser")
			.withOrder(4)
			.build();

		const pending = emitOrFail(client, callMe);
		const deadline = Date.now() + 10_000;
		while (!client.hasPendingStreams) {
			if (Date.now() > deadline) {
				throw new Error("timed out waiting for pending call-back emit");
			}

			await new Promise<void>((resolve) => {
				setTimeout(resolve, 0);
			});
		}

		const servedIds: string[] = [];
		client.serve(async (request) => {
			servedIds.push(TEXT.decode(request.id));

			const reply = await ENGINE.frameBuilder(hexToBytes(replyHex))
				.withId("late-browser-reply")
				.withOrder(9)
				.build();
			return reply;
		});

		const relayed = await pending;
		const result = {
			servedIds,
			relayedIdText: TEXT.decode(relayed.id),
			relayedBodyHex: bytesToHex(relayed.message(ENGINE.opaque)),
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
	readonly rejectionName: string;
	readonly rejectionCode: string;
}

/**
 * The refusal relay: the page handler refuses the server's call-back
 * stream with a chosen gRPC status, and the echo server relays that
 * failure as the answer on the original stream.
 */
export async function muxRefusalRoundTrip(
	url: string,
	serverCertB64: string,
	payloadHex: string,
): Promise<MuxRefusalResult> {
	const result = await withMuxClient(url, serverCertB64, async (client) => {
		client.serve(() => {
			throw new StreamRefusal("NotFound", "nothing here");
		});

		const callMe = await ENGINE.frameBuilder(hexToBytes(payloadHex))
			.withId("call-me-refused-browser")
			.withOrder(4)
			.build();

		try {
			await emitOrFail(client, callMe);
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
	readonly bodyText: string;
	readonly idText: string;
	readonly signatureValid: boolean;
}

/**
 * How the caller observed a gateway work refusal: the structured
 * rejection's name, its `code`, and the transit status it carried.
 */
export interface WorkRefusalResult {
	readonly rejectionName: string;
	readonly rejectionCode: string;
	readonly rejectionStatus: string;
}

/**
 * Build and sign the end-to-end work frame the gateway must forward to
 * the servlet byte-for-byte.
 */
async function signedWorkFrame(
	payloadHex: string,
	idText: string,
	order: number,
	workKey: Secp256k1SigningKey,
): Promise<Frame> {
	const built = await ENGINE.frameBuilder(hexToBytes(payloadHex))
		.withId(idText)
		.withOrder(order)
		.withSigner(workKey)
		.build();
	return built;
}

/**
 * Inputs for a work submission through the cluster gateway: the endpoint
 * and pinned certificate, the servlet target, the signed-frame fields,
 * and the base64 end-to-end work signing key.
 */
export interface WorkRoundTripOptions {
	readonly url: string;
	readonly serverCertB64: string;
	readonly target: string;
	readonly payloadHex: string;
	readonly idText: string;
	readonly order: number;
	readonly workKeyB64: string;
}

export async function workRoundTrip(
	options: WorkRoundTripOptions,
): Promise<WorkRoundTripResult> {
	const { url, serverCertB64, workKeyB64 } = options;
	const workKeyBytes = base64ToBytes(workKeyB64);
	const workKey = ENGINE.signingKey(workKeyBytes);

	const result = await withMuxClient(url, serverCertB64, async (client) => {
		const built = await signedWorkFrame(
			options.payloadHex,
			options.idText,
			options.order,
			workKey,
		);
		const response = await client.submitWork(options.target, built);

		let signatureValid = false;
		try {
			response.verify(workKey.verifyingKey());
			signatureValid = true;
		} catch {
			signatureValid = false;
		}

		return {
			bodyText: TEXT.decode(response.message(ENGINE.opaque)),
			idText: TEXT.decode(response.id),
			signatureValid,
		};
	});
	return result;
}

export async function workRefusal(
	url: string,
	serverCertB64: string,
	target: string,
	payloadHex: string,
	workKeyB64: string,
): Promise<WorkRefusalResult> {
	const workKey = ENGINE.signingKey(base64ToBytes(workKeyB64));

	const result = await withMuxClient(url, serverCertB64, async (client) => {
		const built = await signedWorkFrame(
			payloadHex,
			"e2e-work-refused",
			1,
			workKey,
		);

		try {
			await client.submitWork(target, built);
		} catch (error) {
			if (ENGINE.isTransportError(error)) {
				return {
					rejectionName: error.name,
					rejectionCode: error.code,
					rejectionStatus: error.status ?? "",
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

window.tbRoundTrip = roundTrip;
window.tbSecureRoundTrip = secureRoundTrip;
window.tbMutualRoundTrip = mutualRoundTrip;
window.tbMutualSignerRoundTrip = mutualSignerRoundTrip;
window.tbSignedRoundTrip = signedRoundTrip;
window.tbSealedRoundTrip = sealedRoundTrip;
window.tbCompressedRoundTrip = compressedRoundTrip;
window.tbCompressedSealedRoundTrip = compressedSealedRoundTrip;
window.tbTypedRoundTrip = typedRoundTrip;
/**
 * The concurrent round-trip over the cleartext mux lane: no certificate,
 * symmetric stream cap in place of negotiation.
 */
export async function muxClearConcurrentRoundTrip(
	url: string,
	payloadHex: string,
): Promise<MuxConcurrentResult> {
	const result = await muxConcurrentRoundTrip(url, undefined, payloadHex);
	return result;
}

/**
 * Progressive openStream round-trip: split the Frame DER, push, close.
 */
export async function streamingRoundTrip(
	url: string,
	serverCertB64: string,
	payloadHex: string,
	idText: string,
): Promise<RoundTripResult> {
	const result = await withMuxClient(url, serverCertB64, async (client) => {
		const built = await ENGINE.frameBuilder(hexToBytes(payloadHex))
			.withId(idText)
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

		const outcome = toResult(response);
		return outcome;
	});
	return result;
}

window.tbMuxConcurrentRoundTrip = muxConcurrentRoundTrip;
window.tbMuxCallbackRoundTrip = muxCallbackRoundTrip;
window.tbMuxClearConcurrentRoundTrip = muxClearConcurrentRoundTrip;
window.tbMuxLifecycleProbe = muxLifecycleProbe;
window.tbMuxDrainReason = muxDrainReason;
window.tbStreamingRoundTrip = streamingRoundTrip;
window.tbMuxParkedCallbackRoundTrip = muxParkedCallbackRoundTrip;
window.tbMuxRefusalRoundTrip = muxRefusalRoundTrip;
window.tbWorkRoundTrip = workRoundTrip;
window.tbWorkRefusal = workRefusal;

const status = document.querySelector("#status");
if (status) {
	status.textContent = "client ready";
}
