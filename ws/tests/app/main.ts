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
	TightbeamWsClient,
	TightbeamWsSecureClient,
	ZstdCompression,
	frame,
	wrapped,
} from "@wahidgroup/tightbeam-ws-client";

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
 * The emit surface shared by the cleartext and encrypted clients.
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
 * Open a cleartext client to `url`, run the round-trip body, and always
 * release the socket.
 */
async function withEchoClient<T>(
	url: string,
	run: (client: EmitClient) => Promise<T>,
): Promise<T> {
	const client = await TightbeamWsClient.connect(url);
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
	const client = await TightbeamWsClient.connect(url);
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
	const client = await TightbeamWsSecureClient.connect(
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
	const client = await TightbeamWsSecureClient.connectMutual(
		url,
		base64ToBytes(serverCertB64),
		base64ToBytes(clientCertB64),
		base64ToBytes(clientKeyB64),
	);

	const result = await emitAndDecode(client, payloadHex, idText, order);
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

window.tbRoundTrip = roundTrip;
window.tbSecureRoundTrip = secureRoundTrip;
window.tbMutualRoundTrip = mutualRoundTrip;
window.tbSignedRoundTrip = signedRoundTrip;
window.tbSealedRoundTrip = sealedRoundTrip;
window.tbCompressedRoundTrip = compressedRoundTrip;
window.tbCompressedSealedRoundTrip = compressedSealedRoundTrip;
window.tbTypedRoundTrip = typedRoundTrip;

const status = document.querySelector("#status");
if (status) {
	status.textContent = "client ready";
}
