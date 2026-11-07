/**
 * The facts of the compose stack that the pubsub suites run against, shared
 * by the Playwright specs and the Node vitest lane.
 */

import { requireEnv } from "#ws-env";
import { parseCount, readDialFacts } from "#ws-fixtures";

import { readTopicSecret } from "../fixtures.js";

/**
 * The stack fact that bounds each subscriber queue of the demo servers.
 */
const QUEUE_CAPACITY = "PUBSUB_QUEUE_CAPACITY";

/**
 * The text of {@link QUEUE_CAPACITY}, which the stack always sets.
 */
const queueCapacity = requireEnv(QUEUE_CAPACITY);

/**
 * Every stack fact of the pubsub suites, read once from the environment that
 * `scripts/test-e2e.sh` exports, under the name the stack writes it. Each
 * value has its one home in a `scripts/stack-env.sh`, and a missing or
 * malformed value throws at load.
 */
export const STACK = {
	/**
	 * The multiplexed encrypted pub/sub demo server: answers the `sub/` and
	 * `unsub/` commands, publishes a frame's payload on a `pub/<topic>` id,
	 * pushes a non-topic `notice` stream on a `poke` id, and forbids every
	 * subscribe and every publish under `forbidden/`. The stack runs it
	 * behind the demo session-budget paywall.
	 */
	pubsubEndpoint: requireEnv("PUBSUB_WS_ENDPOINT"),

	/**
	 * The second demo server, whose custom `RelayBackplane` routes every
	 * publish through the backend processor servlet (which uppercases the
	 * payload) before sequencing and fan-out.
	 */
	pubsubProcessedEndpoint: requireEnv("PUBSUB_PROCESSED_WS_ENDPOINT"),

	/**
	 * The demo server's per-subscriber queue bound (`PUBSUB_QUEUE_CAPACITY`
	 * in `pubsub/scripts/stack-env.sh`). A publish burst one past this bound
	 * forces a DropOldest eviction, so the gap tests size themselves from it.
	 */
	pubsubQueueCapacity: parseCount(QUEUE_CAPACITY, queueCapacity),

	/**
	 * The pre-shared key of the topic seal, which the processor seals its
	 * rebuilt frames under.
	 */
	topicSecret: readTopicSecret(requireEnv),

	/**
	 * The stream cap of the stack, and the demo paywall of both demo servers.
	 */
	...readDialFacts(requireEnv),
} as const;
