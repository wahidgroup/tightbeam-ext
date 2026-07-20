/**
 * Message priority levels (V2+). The value of each member is its wire
 * ordinal.
 */

/**
 * The message priority levels.
 */
export const MessagePriority = {
	LowEffort: 0,
	Standard: 1,
	HighThroughput: 2,
	LowLatency: 3,
	Expedited: 4,
	NetworkControl: 5,
} as const;

/**
 * A message priority selector.
 */
export type MessagePriority =
	(typeof MessagePriority)[keyof typeof MessagePriority];

/**
 * The priority levels indexed by wire ordinal.
 */
const PRIORITIES_BY_ORDINAL: readonly MessagePriority[] = [
	MessagePriority.LowEffort,
	MessagePriority.Standard,
	MessagePriority.HighThroughput,
	MessagePriority.LowLatency,
	MessagePriority.Expedited,
	MessagePriority.NetworkControl,
];

/**
 * Narrow a wire ordinal to a {@link MessagePriority}, when in range.
 */
export function priorityFromOrdinal(
	ordinal: number,
): MessagePriority | undefined {
	const priority = PRIORITIES_BY_ORDINAL[ordinal];
	return priority;
}
