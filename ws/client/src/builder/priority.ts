/**
 * Message priority levels (V2+). The value of each member is its wire
 * ordinal.
 */

/**
 * Wire ordinals for frame priority (V2+).
 *
 * Higher ordinals request earlier scheduling under congestion. The peer
 * may still reorder within its local policy.
 */
export const MessagePriority = {
	/**
	 * Lowest effort: defer under load.
	 */
	LowEffort: 0,
	/**
	 * Default application traffic.
	 */
	Standard: 1,
	/**
	 * Bulk throughput over latency.
	 */
	HighThroughput: 2,
	/**
	 * Latency-sensitive application traffic.
	 */
	LowLatency: 3,
	/**
	 * Expedited delivery ahead of ordinary application traffic.
	 */
	Expedited: 4,
	/**
	 * Highest priority: network control and keep-alive traffic.
	 */
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
