/**
 * Frame protocol versions matching tightbeam's `Version` enum.
 */

/**
 * The set of frame versions, ordered lowest to highest. The index of a
 * version in this tuple is its wire ordinal.
 */
export const FRAME_VERSIONS = ["V0", "V1", "V2", "V3"] as const;

/**
 * A frame protocol version selector.
 */
export type FrameVersion = (typeof FRAME_VERSIONS)[number];

/**
 * Returns the ordinal for a version (`V0` -> 0, `V1` -> 1, ...).
 */
export function versionOrdinal(version: FrameVersion): number {
	return FRAME_VERSIONS.indexOf(version);
}
