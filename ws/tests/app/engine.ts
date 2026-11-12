/// <reference types="vite/client" />

/**
 * The engine-load page of the e2e app, whose loads the spec reaches as
 * `window.tbEngine`.
 */

import { ClientTransportError, Engine } from "@wahidgroup/tightbeam-ws-client";

import binaryUrl from "../../client/wasm/tightbeam_ws_wasm_bg.wasm?url";
import { bytesToHex, hexToBytes } from "../fixtures.js";

/**
 * What the engine answered once it loaded: the dotted form of an OID it
 * parsed, and the body of a frame it built.
 */
export interface CustomInputResult {
	/**
	 * The dotted form of the OID that the engine parsed.
	 */
	readonly oid: string;

	/**
	 * The opened body of the frame that the engine built, in hex.
	 */
	readonly bodyHex: string;
}

/**
 * The served binary, fetched and compiled into a `WebAssembly.Module` as the
 * page loads.
 */
const response = await fetch(binaryUrl);
const binary = await response.arrayBuffer();
const compiled = await WebAssembly.compile(binary);

/**
 * Load the engine from the compiled module, as a worker or a CSP-restricted page hands one over, and parse an OID and
 * build a frame of `payloadHex` through it.
 *
 * No other load runs on the page first, and the spec refuses every later fetch of a binary, so a loader that drops the
 * input fails here.
 */
async function initWithInput(payloadHex: string): Promise<CustomInputResult> {
	const engine = await Engine.load(compiled);
	const oid = engine.oid("1.2.840.113549.1.7.1");
	const payload = hexToBytes(payloadHex);
	const builder = engine.frameBuilder(payload).withId("engine-init");
	const built = await builder.build();

	const body = await built.open(engine.opaque);
	const result = { oid: oid.toString(), bodyHex: bytesToHex(body) };
	return result;
}

/**
 * Load the engine from the binary at `source`, which the host does not
 * serve, and answer the code that the load rejects with.
 */
async function initRefusal(source: string): Promise<string> {
	const binary = new URL(source, window.location.href);
	try {
		await Engine.load(binary);
	} catch (error) {
		if (error instanceof ClientTransportError) {
			return error.code;
		}

		return String(error);
	}

	return "";
}

/**
 * The engine loads of the page, which the spec reaches as `window.tbEngine`.
 */
const api = { initWithInput, initRefusal } as const;

/**
 * The engine loads of the page, as `window.tbEngine` holds them.
 */
export type EngineApi = typeof api;

window.tbEngine = api;

const status = document.querySelector("#status");
if (status) {
	status.textContent = "page ready";
}
