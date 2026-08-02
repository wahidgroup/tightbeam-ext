/**
 * Topic names and the pub/sub wire prefixes.
 *
 * Same contract as the Rust `Topic` validation: a topic is non-empty,
 * matched exactly (no wildcards), and never starts with a reserved
 * command prefix, so a topic can never be mistaken for a command.
 */

/**
 * Wire prefix a client subscribes with: `sub/<topic>`.
 */
export const SUB_PREFIX = "sub/";

/**
 * Wire prefix a client unsubscribes with: `unsub/<topic>`.
 */
export const UNSUB_PREFIX = "unsub/";

/**
 * Wire prefix a client publishes with: `pub/<topic>`.
 */
export const PUB_PREFIX = "pub/";

/**
 * Wire prefix the server completes a topic with: `end/<topic>`.
 */
export const END_PREFIX = "end/";

const RESERVED_PREFIXES = [
	SUB_PREFIX,
	UNSUB_PREFIX,
	PUB_PREFIX,
	END_PREFIX,
] as const;

/**
 * Reject a name the server-side `Topic` validation would refuse, before
 * any command frame is built.
 *
 * @throws TypeError for an empty name or a reserved prefix.
 */
export function assertTopic(topic: string): void {
	if (topic.length === 0) {
		throw new TypeError("a topic name must be non-empty");
	}

	for (const prefix of RESERVED_PREFIXES) {
		if (topic.startsWith(prefix)) {
			throw new TypeError(
				`a topic name must not start with the reserved prefix ${prefix}`,
			);
		}
	}
}
