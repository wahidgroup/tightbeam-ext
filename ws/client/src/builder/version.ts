/**
 * Frame protocol versions, mirroring tightbeam's `Version` enum. The value of
 * each member is its wire ordinal.
 */

/**
 * The frame protocol versions.
 */
export const Version = {
	V0: 0,
	V1: 1,
	V2: 2,
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
