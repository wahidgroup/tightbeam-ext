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
 * The cleartext echo server.
 */
export const wsEndpoint = requireEnv("E2E_ECHO_WS_ENDPOINT");

/**
 * The server-authenticated encrypted echo server.
 */
export const secureEndpoint = requireEnv("E2E_ECHO_WS_SECURE_ENDPOINT");

/**
 * The mutually-authenticated encrypted echo server.
 */
export const mutualEndpoint = requireEnv("E2E_ECHO_WS_MUTUAL_ENDPOINT");

/**
 * The sink server: accepts every frame without a response message.
 */
export const sinkEndpoint = requireEnv("E2E_ECHO_WS_SINK_ENDPOINT");

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
