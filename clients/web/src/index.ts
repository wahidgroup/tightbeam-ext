/**
 * Browser client for the tightbeam WebSocket transport.
 */

import init, {
	WsClient,
	sealFrame,
	openFrame,
	inspectFrame,
} from "../wasm/tightbeam_ws_wasm.js";
import type { FrameView } from "../wasm/tightbeam_ws_wasm.js";
import { FrameBuilder } from "@wahidgroup/tightbeam-ts";
import { InternalError } from "@wahidgroup/typing-ts";

import { WasmFrameCodec } from "./codec.js";

export { WsClient, sealFrame, openFrame, inspectFrame };
export { WasmFrameCodec } from "./codec.js";
export { FrameBuilder } from "@wahidgroup/tightbeam-ts";
export type {
	FrameCodec,
	FrameSpec,
	FrameVersion,
	LocalSignerScheme,
	LocalSignerSpec,
	MatrixSpec,
	MessageIntegritySpec,
	MessagePriority,
	PreviousHashSpec,
} from "@wahidgroup/tightbeam-ts";

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

	return builder.withMessage(message);
}

/**
 * A decoded frame: the opaque body plus the metadata and security markers a
 * caller needs to confirm what a peer returned.
 */
export interface OpenedFrame {
	readonly version: number;
	readonly id: Uint8Array;
	readonly order: bigint;
	readonly body: Uint8Array;
	readonly signed: boolean;
	readonly messageIntegrity: boolean;
	readonly frameIntegrity: boolean;
}

/**
 * Copy a wasm {@link FrameView} into a plain {@link OpenedFrame}.
 */
function toOpenedFrame(view: FrameView): OpenedFrame {
	const opened: OpenedFrame = {
		version: view.version,
		id: view.id,
		order: view.order,
		body: view.body,
		signed: view.signed,
		messageIntegrity: view.messageIntegrity,
		frameIntegrity: view.frameIntegrity,
	};

	return opened;
}

let initialization: Promise<void> | undefined;

/**
 * Load the WebAssembly module once. Subsequent calls await the same load.
 */
export async function initClient(
	input?: Parameters<typeof init>[0],
): Promise<void> {
	if (initialization === undefined) {
		initialization = (async (): Promise<void> => {
			await init(input);
		})();
	}

	await initialization;
}

/**
 * A tightbeam client over a single WebSocket connection. Frames are assembled
 * with the fluent {@link frame} builder.
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

		return new TightbeamWsClient(WsClient.connect(url));
	}

	/**
	 * Send a built frame DER (see {@link frame}) and resolve with the decoded
	 * response frame.
	 *
	 * @throws InternalError when the peer returns no response frame.
	 */
	async exchange(frameDer: Uint8Array): Promise<OpenedFrame> {
		const response = await this.socket.request(frameDer);
		if (response === undefined) {
			throw new InternalError(
				"EMPTY_RESPONSE",
				"the peer returned no response frame; expected an echoed frame",
			);
		}

		const view = inspectFrame(response);
		try {
			return toOpenedFrame(view);
		} finally {
			view.free();
		}
	}

	/** Close the underlying socket and release its wasm resources. */
	close(): void {
		this.socket.free();
	}
}
