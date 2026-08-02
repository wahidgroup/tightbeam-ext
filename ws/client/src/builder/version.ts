/**
 * Frame protocol versions. The value of each member is its wire ordinal.
 */

/**
 * Wire ordinals for the frame protocol version floor.
 *
 * Each version admits a larger metadata field set. Structural fields
 * below the floor are rejected at build and decode time.
 */
export const Version = {
	/**
	 * Base envelope: id, order, and message body.
	 */
	V0: 0,
	/**
	 * Adds confidentiality and message integrity.
	 */
	V1: 1,
	/**
	 * Adds priority, lifetime, previous-frame linkage, and frame integrity.
	 */
	V2: 2,
	/**
	 * Adds the routing matrix.
	 */
	V3: 3,
} as const;

/**
 * A frame protocol version selector.
 */
export type Version = (typeof Version)[keyof typeof Version];

/**
 * Narrow a wire ordinal to a {@link Version}, when in range.
 */
export function versionFromOrdinal(ordinal: number): Version | undefined {
	if (ordinal === Version.V0) {
		return Version.V0;
	}
	if (ordinal === Version.V1) {
		return Version.V1;
	}
	if (ordinal === Version.V2) {
		return Version.V2;
	}
	if (ordinal === Version.V3) {
		return Version.V3;
	}

	return undefined;
}
