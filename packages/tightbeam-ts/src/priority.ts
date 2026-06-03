/**
 * Message priority levels (V2+), mirroring tightbeam's `MessagePriority` enum.
 */

/**
 * The set of message priority levels, ordered lowest to highest.
 */
export const MESSAGE_PRIORITIES = [
	"LowEffort",
	"Standard",
	"HighThroughput",
	"LowLatency",
	"Expedited",
	"NetworkControl",
] as const;

/**
 * A message priority selector.
 */
export type MessagePriority = (typeof MESSAGE_PRIORITIES)[number];

/**
 * Returns the on-the-wire ordinal for a priority (`LowEffort` -> 0, ...).
 */
export function priorityOrdinal(priority: MessagePriority): number {
	return MESSAGE_PRIORITIES.indexOf(priority);
}
