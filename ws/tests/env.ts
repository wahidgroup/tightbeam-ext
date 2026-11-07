/**
 * Environment and identity-fixture resolution shared by the ws and pubsub
 * suites. The ws suites import this module by its relative path, and the
 * pubsub suites as `#ws-env`. All values come from the environment that
 * `scripts/test-e2e.sh` exports from the stack env file, under the names the
 * stack writes them.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import type {
	MutualIdentity,
	TransportSigner,
} from "@wahidgroup/tightbeam-ws-client";

/**
 * Read a required stack variable, failing fast when the suite is run
 * without the stack environment.
 */
export function requireEnv(name: string): string {
	const value = process.env[name];
	if (value === undefined) {
		throw new Error(
			`${name} is not set; run the suite via scripts/test-e2e.sh`,
		);
	}

	return value;
}

/**
 * Read an identity fixture as raw bytes.
 */
export function certBytes(name: string): Uint8Array {
	return readFileSync(join(requireEnv("CERT_DIR"), name));
}

/**
 * Read an identity fixture as base64 for the `page.evaluate` boundary or a
 * page's query parameter.
 */
export function certBase64(name: string): string {
	return readFileSync(join(requireEnv("CERT_DIR"), name)).toString("base64");
}

/**
 * The demo client identity: the pinned server certificate, the client
 * certificate, and the proof of its key, the raw fixture scalar unless a
 * signer stands in for it.
 */
export function demoIdentity(
	clientKey: Uint8Array | TransportSigner = certBytes("client.key"),
): MutualIdentity {
	const identity = {
		serverCertDer: certBytes("server.cert.der"),
		clientCertDer: certBytes("client.cert.der"),
		clientKey,
	};
	return identity;
}
