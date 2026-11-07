/// <reference types="vite/client" />

/**
 * The engine-load page of the e2e app. It loads the engine from a custom
 * module input, the way a worker or a CSP-restricted page hands one over, and
 * no other load runs on the page first, so the engine it reports came from
 * that input.
 *
 * The page compiles the binary as it loads, and the spec then refuses every
 * later fetch of a binary, so a loader that drops the input fails the load.
 * A load from a binary the host does not serve fails for real, and the page
 * reports the code of that failure.
 */

import {
	ClientTransportError,
	TightbeamWsClient,
} from "@wahidgroup/tightbeam-ws-client";

import binaryUrl from "../../client/wasm/tightbeam_ws_wasm_bg.wasm?url";
import { bytesToHex, hexToBytes } from "../fixtures.js";

/**
 * What the engine answered once it loaded: the dotted form of an OID it
 * parsed, and the body of a frame it built.
 */
export interface CustomInputResult {
	readonly oid: string;
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
 * Load the engine from the compiled module, and parse an OID and build a
 * frame of `payloadHex` through the engine.
 */
export async function initWithInput(
	payloadHex: string,
): Promise<CustomInputResult> {
	const engine = await TightbeamWsClient.init(compiled);
	const oid = engine.oid("1.2.840.113549.1.7.1");
	const payload = hexToBytes(payloadHex);
	const builder = engine.frameBuilder(payload);
	const built = await builder.build();

	const body = built.message(engine.opaque);
	const result = { oid: oid.toString(), bodyHex: bytesToHex(body) };
	return result;
}

/**
 * Load the engine from the binary at `source`, which the host does not
 * serve, and answer the code that `init` rejects with.
 */
export async function initRefusal(source: string): Promise<string> {
	const binary = new URL(source, window.location.href);
	try {
		await TightbeamWsClient.init(binary);
	} catch (error) {
		if (error instanceof ClientTransportError) {
			return error.code;
		}

		return String(error);
	}

	return "";
}

window.tbInitWithInput = initWithInput;
window.tbInitRefusal = initRefusal;

const status = document.querySelector("#status");
if (status) {
	status.textContent = "page ready";
}
