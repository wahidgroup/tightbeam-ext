/**
 * The stack environment of the Node lanes of the ws and pubsub suites. Each
 * value comes, under the name the stack writes, from the environment that
 * `scripts/test-e2e.sh` exports from the stack env file.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { MutualIdentity, TransportSigner } from "@wahidgroup/tightbeam-ws-client";

import { StackFacts } from "./fixtures.js";

/**
 * The stack facts of the environment. A fact the environment lacks throws
 * at its read, so a suite run without the stack fails fast.
 */
export const ENVIRONMENT = StackFacts.over((name) => process.env[name], "the environment of scripts/test-e2e.sh");

/**
 * The identity fixtures of the stack, under the `CERT_DIR` that the stack
 * env file names.
 */
export class Identities {
	static #stack: Identities | undefined;

	readonly #dir: string;

	private constructor(dir: string) {
		this.#dir = dir;
	}

	/**
	 * The identity fixtures of the stack, read once on first use.
	 *
	 * @throws Error when the environment names no `CERT_DIR`.
	 */
	static get stack(): Identities {
		Identities.#stack ??= new Identities(ENVIRONMENT.text("CERT_DIR"));
		return Identities.#stack;
	}

	/**
	 * The fixture `name` as raw bytes.
	 */
	bytes(name: string): Uint8Array {
		const bytes = new Uint8Array(readFileSync(join(this.#dir, name)));
		return bytes;
	}

	/**
	 * The fixture `name` as base64, for the `page.evaluate` boundary or the
	 * query parameter of a page.
	 */
	base64(name: string): string {
		const base64 = readFileSync(join(this.#dir, name)).toString("base64");
		return base64;
	}

	/**
	 * The demo client identity: the pinned server certificate, the client
	 * certificate, and the proof of its key, the raw fixture scalar unless a
	 * signer stands in for it.
	 */
	demo(clientKey?: Uint8Array | TransportSigner): MutualIdentity {
		const identity = {
			serverCertDer: this.bytes("server.cert.der"),
			clientCertDer: this.bytes("client.cert.der"),
			clientKey: clientKey ?? this.bytes("client.key"),
		};
		return identity;
	}
}
