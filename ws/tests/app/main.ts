/**
 * Minimal, headless example app for the generic tightbeam-ws client.
 *
 * Builds frames with the fluent {@link frame} builder, ships them over the
 * socket, and surfaces the decoded response so the Playwright spec can assert
 * the body and metadata survived the round-trip.
 */

import type { Frame, MessageCodec } from "@wahidgroup/tightbeam-ws-client";
import {
	Aes256Gcm,
	Opaque,
	Secp256k1SigningKey,
	Sha3_256,
	StreamRefusal,
	TightbeamWsClient,
	ZstdCompression,
	frame,
	isTransportError,
	wrapped,
} from "@wahidgroup/tightbeam-ws-client";

import { NobleTransportSigner } from "../signer.js";

const TEXT = new TextDecoder();

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

function hexToBytes(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i += 1) {
		bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}

	return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
	let hex = "";
	for (const byte of bytes) {
		hex += byte.toString(16).padStart(2, "0");
	}

	return hex;
}

function base64ToBytes(base64: string): Uint8Array {
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i);
	}

	return bytes;
}

/**
 * The emit surface of the multiplexed client, cleartext or encrypted.
 */
interface EmitClient {
	emit(frame: Frame): Promise<Frame | undefined>;
	close(): void;
}

/**
 * Emit `frame` and return the response frame.
 */
async function emitFrame(client: EmitClient, built: Frame): Promise<Frame> {
	const response = await client.emit(built);
	if (response === undefined) {
		throw new Error("the peer returned no response frame");
	}

	return response;
}

function toResult(response: Frame): RoundTripResult {
	return {
		bodyHex: bytesToHex(response.message(Opaque)),
		version: response.version,
		idText: TEXT.decode(response.id),
		order: response.order.toString(),
		signed: response.signed,
		messageIntegrity: response.messageIntegrity,
		frameIntegrity: response.frameIntegrity,
	};
}

async function emitAndDecode(
	client: EmitClient,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<RoundTripResult> {
	try {
		const built = await frame(hexToBytes(payloadHex))
			.withId(idText)
			.withOrder(order)
			.build();

		return toResult(await emitFrame(client, built));
	} finally {
		client.close();
	}
}

/**
 * Open a cleartext multiplexed client to `url`, run the round-trip body,
 * and always release the socket.
 */
async function withEchoClient<T>(
	url: string,
	run: (client: EmitClient) => Promise<T>,
): Promise<T> {
	const client = await TightbeamWsClient.connectCleartext(url);
	try {
		return await run(client);
	} finally {
		client.close();
	}
}

async function roundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<RoundTripResult> {
	const client = await TightbeamWsClient.connectCleartext(url);
	const result = await emitAndDecode(client, payloadHex, idText, order);
	return result;
}

async function secureRoundTrip(
	url: string,
	serverCertB64: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<RoundTripResult> {
	const client = await TightbeamWsClient.connect(
		url,
		base64ToBytes(serverCertB64),
	);

	const result = await emitAndDecode(client, payloadHex, idText, order);
	return result;
}

async function mutualRoundTrip(
	url: string,
	serverCertB64: string,
	clientCertB64: string,
	clientKeyB64: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<RoundTripResult> {
	const client = await TightbeamWsClient.connectMutual(
		url,
		base64ToBytes(serverCertB64),
		base64ToBytes(clientCertB64),
		base64ToBytes(clientKeyB64),
	);

	const result = await emitAndDecode(client, payloadHex, idText, order);
	return result;
}

/**
 * The mutual round-trip outcome plus how many prehashes the external
 * signer answered, proving the handshake used it.
 */
export interface SignerRoundTripResult extends RoundTripResult {
	readonly signatures: number;
}

async function mutualSignerRoundTrip(
	url: string,
	serverCertB64: string,
	clientCertB64: string,
	clientKeyB64: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<SignerRoundTripResult> {
	const signer = new NobleTransportSigner(base64ToBytes(clientKeyB64));

	const client = await TightbeamWsClient.connectMutual(
		url,
		base64ToBytes(serverCertB64),
		base64ToBytes(clientCertB64),
		signer,
	);

	const decoded = await emitAndDecode(client, payloadHex, idText, order);
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

async function signedRoundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
	signingKeyHex: string,
	saltHex: string,
): Promise<SignedRoundTripResult> {
	const signingKey = Secp256k1SigningKey.fromBytes(hexToBytes(signingKeyHex));
	const salt = hexToBytes(saltHex);

	const response = await withEchoClient(url, async (client) => {
		const built = await frame(hexToBytes(payloadHex))
			.withId(idText)
			.withOrder(order)
			.withMessageHasher(new Sha3_256(), salt)
			.withWitnessHasher(new Sha3_256())
			.withSigner(signingKey)
			.build();
		return emitFrame(client, built);
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
		wrongSaltVerdict: await response.messageCommitmentVerdict(
			hexToBytes("deadbeef"),
		),
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

async function sealedRoundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
	keyHex: string,
): Promise<SealedRoundTripResult> {
	const payload = hexToBytes(payloadHex);
	const cipher = Aes256Gcm.fromKey(hexToBytes(keyHex));

	const response = await withEchoClient(url, async (client) => {
		const built = await frame(payload)
			.withId(idText)
			.withOrder(order)
			.withEncryptor(cipher)
			.build();

		return emitFrame(client, built);
	});

	return {
		confidential: response.confidential,
		confidentialityOid: response.confidentialityInfo?.algorithmOid ?? "",
		ciphertextDiffers: bytesToHex(response.bodyDer) !== payloadHex,
		decryptedHex: bytesToHex(await response.decryptMessage(cipher, Opaque)),
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

async function compressedRoundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
): Promise<CompressedRoundTripResult> {
	const zstd = new ZstdCompression();

	const response = await withEchoClient(url, async (client) => {
		const built = await frame(hexToBytes(payloadHex))
			.withId(idText)
			.withOrder(order)
			.withCompressor(zstd)
			.build();

		return emitFrame(client, built);
	});

	const inflated = await response.inflateMessage(zstd, Opaque);
	return {
		compressed: response.compressed,
		compactnessOid: response.compactnessInfo?.algorithmOid ?? "",
		inflatedHex: bytesToHex(inflated),
	};
}

async function compressedSealedRoundTrip(
	url: string,
	payloadHex: string,
	idText: string,
	order: number,
	keyHex: string,
): Promise<CompressedRoundTripResult> {
	const zstd = new ZstdCompression();
	const cipher = Aes256Gcm.fromKey(hexToBytes(keyHex));

	const response = await withEchoClient(url, async (client) => {
		const built = await frame(hexToBytes(payloadHex))
			.withId(idText)
			.withOrder(order)
			.withCompressor(zstd)
			.withEncryptor(cipher)
			.build();

		return emitFrame(client, built);
	});

	const inflated = await response.decryptMessage(cipher, Opaque, zstd);
	return {
		compressed: response.compressed,
		compactnessOid: response.compactnessInfo?.algorithmOid ?? "",
		inflatedHex: bytesToHex(inflated),
	};
}

/**
 * A chat message round-tripped as a typed body: JSON under a wrapped
 * payload codec, decoded and runtime-validated in the browser.
 */
export interface TypedRoundTripResult {
	readonly author: string;
	readonly text: string;
}

const Chat: MessageCodec<TypedRoundTripResult> = wrapped({
	encode(message: TypedRoundTripResult): Uint8Array {
		const payload = new TextEncoder().encode(JSON.stringify(message));
		return payload;
	},
	decode(payload: Uint8Array): TypedRoundTripResult {
		const parsed: unknown = JSON.parse(TEXT.decode(payload));
		if (
			typeof parsed !== "object" ||
			parsed === null ||
			!("author" in parsed) ||
			!("text" in parsed)
		) {
			throw new Error("not a chat message");
		}

		const { author, text } = parsed;
		if (typeof author !== "string" || typeof text !== "string") {
			throw new Error("not a chat message");
		}

		const message = { author, text };
		return message;
	},
});

async function typedRoundTrip(
	url: string,
	idText: string,
	order: number,
	author: string,
	text: string,
): Promise<TypedRoundTripResult> {
	const response = await withEchoClient(url, async (client) => {
		const built = await frame()
			.withId(idText)
			.withOrder(order)
			.withMessage(Chat, { author, text })
			.build();

		return emitFrame(client, built);
	});

	const message = response.message(Chat);
	return message;
}

/**
 * Open a multiplexed client to `url`, run the exchange body, and always
 * release the socket.
 */
async function withMuxClient<T>(
	url: string,
	serverCertB64: string | undefined,
	run: (client: TightbeamWsClient) => Promise<T>,
): Promise<T> {
	let client: TightbeamWsClient;
	if (serverCertB64 === undefined) {
		client = await TightbeamWsClient.connectCleartext(url);
	} else {
		client = await TightbeamWsClient.connect(
			url,
			base64ToBytes(serverCertB64),
		);
	}

	try {
		return await run(client);
	} finally {
		client.close();
	}
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

async function muxConcurrentRoundTrip(
	url: string,
	serverCertB64: string | undefined,
	payloadHex: string,
): Promise<MuxConcurrentResult> {
	const payload = hexToBytes(payloadHex);
	const labels = ["mux-browser-1", "mux-browser-2", "mux-browser-3"];

	return withMuxClient(url, serverCertB64, async (client) => {
		const emits = labels.map(async (label, index) => {
			const built = await frame(indexedBody(payload, index))
				.withId(label)
				.withOrder(index + 1)
				.build();

			const response = await emitFrame(client, built);
			return response;
		});
		const echoed = await Promise.all(emits);

		const result = {
			echoedIds: echoed.map((response) => TEXT.decode(response.id)),
			echoedBodiesHex: echoed.map((response) =>
				bytesToHex(response.message(Opaque)),
			),
		};
		return result;
	});
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

async function muxCallbackRoundTrip(
	url: string,
	serverCertB64: string,
	payloadHex: string,
	replyHex: string,
): Promise<MuxCallbackResult> {
	return withMuxClient(url, serverCertB64, async (client) => {
		const servedIds: string[] = [];
		client.serve(async (request) => {
			servedIds.push(TEXT.decode(request.id));

			const reply = await frame(hexToBytes(replyHex))
				.withId("browser-reply")
				.withOrder(9)
				.build();
			return reply;
		});

		// The `call-me` id makes the server open its own stream back to
		// this page. The handler's reply rides the original stream.
		const callMe = await frame(hexToBytes(payloadHex))
			.withId("call-me-browser")
			.withOrder(4)
			.build();
		const relayed = await emitFrame(client, callMe);

		const result = {
			servedIds,
			relayedIdText: TEXT.decode(relayed.id),
			relayedBodyHex: bytesToHex(relayed.message(Opaque)),
		};
		return result;
	});
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

async function muxLifecycleProbe(
	url: string,
	serverCertB64: string,
): Promise<MuxLifecycleResult> {
	return withMuxClient(url, serverCertB64, async (client) => {
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

		await client.shutdownWith("EnhanceYourCalm");

		let drainCode = "";
		try {
			const after = await frame(new Uint8Array([0xb0, 0x1f]))
				.withId("browser-after-calm")
				.withOrder(1)
				.build();
			await client.emit(after);
		} catch (error) {
			if (isTransportError(error)) {
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

async function muxDrainReason(
	url: string,
	serverCertB64: string,
): Promise<MuxDrainResult> {
	return withMuxClient(url, serverCertB64, async (client) => {
		/*
		 * The `drain-calm` id makes the server drain the session with an
		 * EnhanceYourCalm GoAway instead of echoing. The drain stops the
		 * server's writer before the response, so the emit never settles
		 * on its own and is aborted once the reason surfaces.
		 */
		const drain = await frame(new Uint8Array([0xb0, 0x1d]))
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
}

/**
 * The parked variant of the call-back exchange: the trigger goes out
 * before any handler registers, proving early server streams wait for
 * `serve` instead of being dropped.
 */
async function muxParkedCallbackRoundTrip(
	url: string,
	serverCertB64: string,
	payloadHex: string,
	replyHex: string,
): Promise<MuxCallbackResult> {
	return withMuxClient(url, serverCertB64, async (client) => {
		/*
		 * Fire the call-back trigger with no handler registered and give
		 * the server's stream time to arrive and park. No parked-count
		 * surface exists to poll: a sleep too short degrades this into
		 * the ordinary served path (still passing, weaker), never into
		 * a flake.
		 */
		const callMe = await frame(hexToBytes(payloadHex))
			.withId("call-me-parked-browser")
			.withOrder(4)
			.build();
		const pending = emitFrame(client, callMe);
		await new Promise((resolve) => setTimeout(resolve, 100));

		const servedIds: string[] = [];
		client.serve(async (request) => {
			servedIds.push(TEXT.decode(request.id));

			const reply = await frame(hexToBytes(replyHex))
				.withId("late-browser-reply")
				.withOrder(9)
				.build();
			return reply;
		});

		const relayed = await pending;
		const result = {
			servedIds,
			relayedIdText: TEXT.decode(relayed.id),
			relayedBodyHex: bytesToHex(relayed.message(Opaque)),
		};
		return result;
	});
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
async function muxRefusalRoundTrip(
	url: string,
	serverCertB64: string,
	payloadHex: string,
): Promise<MuxRefusalResult> {
	return withMuxClient(url, serverCertB64, async (client) => {
		client.serve(() => {
			throw new StreamRefusal("NotFound", "nothing here");
		});

		const callMe = await frame(hexToBytes(payloadHex))
			.withId("call-me-refused-browser")
			.withOrder(4)
			.build();

		try {
			await emitFrame(client, callMe);
		} catch (error) {
			if (isTransportError(error)) {
				return { rejectionName: error.name, rejectionCode: error.code };
			}
			return { rejectionName: String(error), rejectionCode: "" };
		}
		return { rejectionName: "", rejectionCode: "" };
	});
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
async function muxClearConcurrentRoundTrip(
	url: string,
	payloadHex: string,
): Promise<MuxConcurrentResult> {
	const result = await muxConcurrentRoundTrip(url, undefined, payloadHex);
	return result;
}

window.tbMuxConcurrentRoundTrip = muxConcurrentRoundTrip;
window.tbMuxCallbackRoundTrip = muxCallbackRoundTrip;
window.tbMuxClearConcurrentRoundTrip = muxClearConcurrentRoundTrip;
window.tbMuxLifecycleProbe = muxLifecycleProbe;
window.tbMuxDrainReason = muxDrainReason;
window.tbMuxParkedCallbackRoundTrip = muxParkedCallbackRoundTrip;
window.tbMuxRefusalRoundTrip = muxRefusalRoundTrip;

const status = document.querySelector("#status");
if (status) {
	status.textContent = "client ready";
}
