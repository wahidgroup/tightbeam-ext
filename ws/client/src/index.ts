/**
 * Client for the tightbeam WebSocket transport (browser and Node).
 */

import init, { SecureWsClient, WsClient } from "#wasm";

import { FrameBuilder } from "./builder/index.js";
import { WasmFrameCodec } from "./codec.js";
import { Frame } from "./frame.js";

export { SecureWsClient, WsClient };
export { InternalError } from "./errors.js";
export { WasmFrameCodec } from "./codec.js";
export { Frame, INTEGRITY_VERDICTS } from "./frame.js";
export type {
	ConfidentialityInfo,
	DigestInfo,
	FrameMatrix,
	IntegrityVerdict,
	PreviousFrame,
	SignatureInfo,
} from "./frame.js";
export {
	Aes256Gcm,
	EciesDecryptor,
	EciesEncryptor,
	PROFILE_OIDS,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	Sha3_256,
} from "./crypto.js";
export type {
	BodyDecryptor,
	BodyEncryptor,
	EncryptedBody,
	Hasher,
	Signatory,
} from "./crypto.js";
export {
	FrameBuilder,
	MessagePriority,
	ValidationError,
	Version,
	priorityFromOrdinal,
	versionFromOrdinal,
} from "./builder/index.js";
export type {
	FrameCodec,
	FrameSpec,
	MatrixSpec,
	MessageIntegritySpec,
	PreviousHashSpec,
	ValidationIssue,
} from "./builder/index.js";

/**
 * The wasm-backed codec shared by {@link frame}.
 */
const sharedCodec = new WasmFrameCodec();

/**
 * Begin building a tightbeam frame with the fluent, Rust-parity builder,
 * backed by the WebAssembly codec.
 *
 * The wasm module MUST be initialized via {@link initClient} before calling
 * {@link FrameBuilder.build}.
 */
export function frame(message?: Uint8Array): FrameBuilder {
	const builder = new FrameBuilder(sharedCodec);
	if (message === undefined) {
		return builder;
	}

	const builderWithMessage = builder.withMessage(message);
	return builderWithMessage;
}

/**
 * The request surface shared by the cleartext and encrypted wasm sockets.
 */
interface FrameSocket {
	request(frameDer: Uint8Array): Promise<Uint8Array | undefined>;
	free(): void;
}

/**
 * Send a frame over `socket` and decode the response: resolves with
 * `undefined` when the peer returns no response frame.
 */
async function emitFrame(
	socket: FrameSocket,
	frame: Frame,
): Promise<Frame | undefined> {
	const response = await socket.request(frame.toDer());
	if (response === undefined) {
		return undefined;
	}

	const result = Frame.fromDer(response);
	return result;
}

let initialization: Promise<void> | undefined;

/**
 * Load the WebAssembly module once. Subsequent calls await the same load.
 *
 * Under Node the module is compiled synchronously at import time (the
 * `nodejs` wasm-pack target), so this resolves immediately.
 */
export async function initClient(
	input?: Parameters<typeof init>[0],
): Promise<void> {
	if (initialization === undefined) {
		initialization = (async (): Promise<void> => {
			const load: unknown = init;
			if (typeof load === "function") {
				await init(input);
			}
		})();
	}

	await initialization;
}

/**
 * A tightbeam client over a single WebSocket connection. Frames are
 * assembled with the fluent {@link frame} builder.
 */
export class TightbeamWsClient {
	private readonly socket: WsClient;

	private constructor(socket: WsClient) {
		this.socket = socket;
	}

	/**
	 * Initialize the module (if needed) and open a socket to `url`.
	 *
	 * @param url - The WebSocket URL to connect to.
	 * @returns A new {@link TightbeamWsClient} instance.
	 */
	static async connect(url: string): Promise<TightbeamWsClient> {
		await initClient();

		let client = new TightbeamWsClient(WsClient.connect(url));
		return client;
	}

	/**
	 * Send a built {@link Frame} and resolve with the decoded response
	 * frame. Resolves with `undefined` when the peer returns no response frame.
	 */
	async emit(frame: Frame): Promise<Frame | undefined> {
		const result = await emitFrame(this.socket, frame);
		return result;
	}

	/*
	 * Close the underlying socket and release its wasm resources.
	 */
	close(): void {
		this.socket.free();
	}
}

/**
 * A tightbeam client over a single ECIES-encrypted WebSocket session.
 *
 * The server is authenticated by pinning its DER certificate as the sole
 * trust anchor. {@link connectMutual} presents a client identity so the server
 * can authenticate this client.
 */
export class TightbeamWsSecureClient {
	private readonly socket: SecureWsClient;

	private constructor(socket: SecureWsClient) {
		this.socket = socket;
	}

	/**
	 * Initialize the module (if needed) and open a server-authenticated
	 * encrypted session to `url`.
	 *
	 * @param url - The WebSocket URL to connect to.
	 * @param serverCertDer - DER certificate pinned as the trusted server.
	 */
	static async connect(
		url: string,
		serverCertDer: Uint8Array,
	): Promise<TightbeamWsSecureClient> {
		await initClient();

		let client = new TightbeamWsSecureClient(
			SecureWsClient.connect(url, serverCertDer),
		);
		return client;
	}

	/**
	 * As {@link connect}, additionally presenting a client identity for
	 * mutual authentication.
	 *
	 * @param url - The WebSocket URL to connect to.
	 * @param serverCertDer - DER certificate pinned as the trusted server.
	 * @param clientCertDer - DER certificate presented to the server.
	 * @param clientSigningKey - Raw 32-byte secp256k1 signing scalar.
	 */
	static async connectMutual(
		url: string,
		serverCertDer: Uint8Array,
		clientCertDer: Uint8Array,
		clientSigningKey: Uint8Array,
	): Promise<TightbeamWsSecureClient> {
		await initClient();

		let client = new TightbeamWsSecureClient(
			SecureWsClient.connectMutual(
				url,
				serverCertDer,
				clientCertDer,
				clientSigningKey,
			),
		);
		return client;
	}

	/**
	 * Send a built {@link Frame} over the encrypted session and resolve
	 * with the decoded response frame. The first call performs the ECIES
	 * handshake.
	 *
	 * Resolves with `undefined` when the peer returns no response frame.
	 */
	async emit(frame: Frame): Promise<Frame | undefined> {
		const result = await emitFrame(this.socket, frame);
		return result;
	}

	/**
	 * Close the underlying socket and release its wasm resources.
	 */
	close(): void {
		this.socket.free();
	}
}
