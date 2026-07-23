/**
 * Endpoint and identity-fixture resolution shared by the Playwright specs
 * and the Node vitest lane. All values come from the environment rendered
 * by `scripts/test-e2e.sh`.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Read a required stack variable, failing fast when the suite is run
 * without the stack environment.
 */
function requireEnv(name: string): string {
	const value = process.env[name];
	if (value === undefined) {
		throw new Error(
			`${name} is not set; run the suite via scripts/test-e2e.sh`,
		);
	}

	return value;
}

/**
 * The multiplexed encrypted echo server: serves concurrent streams,
 * calls the client back when a frame id starts with `call-me`, accepts
 * without a response frame on a `sink` id, and drains the session on a
 * `drain-calm` id.
 */
export const muxEndpoint = requireEnv("E2E_ECHO_WS_MUX_ENDPOINT");

/**
 * The multiplexed cleartext echo server: same behavior as the encrypted
 * one, with a symmetric stream cap of 8 in place of negotiation.
 */
export const muxClearEndpoint = requireEnv("E2E_ECHO_WS_MUX_CLEAR_ENDPOINT");

/**
 * The mutually-authenticated multiplexed encrypted echo server: as the
 * encrypted one, additionally requiring the pinned client certificate.
 */
export const muxMutualEndpoint = requireEnv("E2E_ECHO_WS_MUX_MUTUAL_ENDPOINT");

/**
 * Read an identity fixture as raw bytes.
 */
export function certBytes(name: string): Uint8Array {
	return readFileSync(join(requireEnv("E2E_CERT_DIR"), name));
}

/**
 * Read an identity fixture as base64 for the `page.evaluate` boundary.
 */
export function certBase64(name: string): string {
	return readFileSync(join(requireEnv("E2E_CERT_DIR"), name)).toString(
		"base64",
	);
}
