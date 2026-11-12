/**
 * The facts of the compose stack that the pubsub suites run against, shared
 * by the Playwright specs and the Node vitest lane.
 */

import { ENVIRONMENT, Identities } from "#ws-env";
import { DialFacts } from "#ws-fixtures";

import type { BoardMode } from "../fixtures.js";
import { BoardQuery, TopicSecret } from "../fixtures.js";

/**
 * Every stack fact of the pubsub suites, read once from the environment that
 * `scripts/test-e2e.sh` exports, under the name the stack writes it. Each
 * value has its one home in a `scripts/stack-env.sh`, and a missing or
 * malformed value throws at load.
 */
export const STACK = {
	/**
	 * The endpoint of the demo server, which `docs/pubsub.md` (Testing)
	 * describes.
	 */
	pubsubEndpoint: ENVIRONMENT.text("PUBSUB_WS_ENDPOINT"),

	/**
	 * The endpoint of the second demo server, which relays every publish
	 * through the processor servlet.
	 */
	pubsubProcessedEndpoint: ENVIRONMENT.text("PUBSUB_PROCESSED_WS_ENDPOINT"),

	/**
	 * The demo server's per-subscriber queue bound (`PUBSUB_QUEUE_CAPACITY`
	 * in `pubsub/scripts/stack-env.sh`). A publish burst one past this bound
	 * forces a DropOldest eviction, so the gap tests size themselves from it.
	 */
	pubsubQueueCapacity: ENVIRONMENT.count("PUBSUB_QUEUE_CAPACITY"),

	/**
	 * The pre-shared key of the topic seal, which the processor seals its
	 * rebuilt frames under.
	 */
	topicSecret: TopicSecret.read(ENVIRONMENT),

	/**
	 * The stream cap of the stack, and the demo paywall of both demo servers.
	 */
	dial: DialFacts.read(ENVIRONMENT),

	/**
	 * The path of the board page that dials the `endpoint` of `board` with the
	 * demo identity and subscribes to its `topic` in its `mode`.
	 */
	boardPath(board: { readonly endpoint: string; readonly topic: string; readonly mode: BoardMode }): string {
		const identities = Identities.stack;
		const query = new BoardQuery({
			...board,
			identity: {
				serverCertDer: identities.base64("server.cert.der"),
				clientCertDer: identities.base64("client.cert.der"),
				clientKey: identities.base64("client.key"),
			},
			dial: STACK.dial,
			secret: STACK.topicSecret,
		});

		const path = `/${query.search()}`;
		return path;
	},
} as const;
