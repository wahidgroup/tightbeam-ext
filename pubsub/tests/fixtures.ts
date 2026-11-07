/**
 * Fixtures of the pubsub e2e stack, shared by the board page and the Node
 * suites. The fixtures that the ws stack owns come from `#ws-fixtures`.
 */

import type { SharedKey } from "@wahidgroup/tightbeam-ws-client";

import type { FactSource } from "#ws-fixtures";
import { bytesToHex, hexToBytes } from "#ws-fixtures";

/**
 * The stack fact that spells the key of the processed topic in hex.
 */
const TOPIC_KEY = "PUBSUB_TOPIC_KEY";

/**
 * The stack fact that names the key of the processed topic in each sealed
 * envelope.
 */
const TOPIC_KEY_ID = "PUBSUB_TOPIC_KEY_ID";

/**
 * The pre-shared AES-256-GCM key and its identifier that `source` holds: the
 * topic seal on sealed boards and frames, and the key the processor servlet
 * seals rebuilt frames under, both from `pubsub/scripts/stack-env.sh`.
 */
export function readTopicSecret(source: FactSource): SharedKey {
	const key = hexToBytes(source(TOPIC_KEY));
	const keyId = new TextEncoder().encode(source(TOPIC_KEY_ID));

	const secret = { key, keyId };
	return secret;
}

/**
 * `secret` as text under the names of its facts, for the query string of a
 * page that reads it back through {@link readTopicSecret}.
 */
export function topicSecretParams(secret: SharedKey): Record<string, string> {
	const params = {
		[TOPIC_KEY]: bytesToHex(secret.key),
		[TOPIC_KEY_ID]: new TextDecoder().decode(secret.keyId),
	};
	return params;
}
