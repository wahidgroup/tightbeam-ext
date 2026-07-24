/**
 * Endpoint and identity-fixture resolution for the pubsub suites. Values
 * come from the environment rendered by `scripts/test-e2e.sh`.
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
 * The multiplexed encrypted pub/sub demo server: answers the `sub/` and
 * `unsub/` commands, publishes a frame's payload on a `pub/<topic>` id,
 * pushes a non-topic `notice` stream on a `poke` id, quiesces the
 * registry on a `quiesce` id, and forbids every topic under `forbidden/`.
 */
export const pubsubEndpoint = requireEnv("E2E_PUBSUB_WS_ENDPOINT");

/**
 * The second demo server, whose custom `RelayBackplane` routes every
 * publish through the backend processor servlet (which uppercases the
 * payload) before sequencing and fan-out.
 */
export const pubsubProcessedEndpoint = requireEnv(
	"E2E_PUBSUB_PROCESSED_WS_ENDPOINT",
);

/**
 * The demo server's per-subscriber queue bound (`PUBSUB_QUEUE_CAPACITY`
 * in `pubsub/scripts/stack-env.sh`). A publish burst one past this bound
 * forces a DropOldest eviction, so the gap tests size themselves from it.
 */
export const pubsubQueueCapacity = Number(
	requireEnv("E2E_PUBSUB_QUEUE_CAPACITY"),
);

/**
 * Read an identity fixture as raw bytes.
 */
export function certBytes(name: string): Uint8Array {
	return readFileSync(join(requireEnv("E2E_CERT_DIR"), name));
}

/**
 * Read an identity fixture as base64 for the board app's `cert` query
 * parameter.
 */
export function certBase64(name: string): string {
	return readFileSync(join(requireEnv("E2E_CERT_DIR"), name)).toString(
		"base64",
	);
}
