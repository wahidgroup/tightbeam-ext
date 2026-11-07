import { describe, expect, expectTypeOf, it } from "vitest";

import type { ZstdView } from "./compress.js";
import type { Sha3_256 } from "./crypto.js";
import type { OidView, ProfileView } from "./views.js";
import { TightbeamWsClient } from "./index.js";

/**
 * The realm-shared members of the engine. The engine of the realm owns each
 * handle, so each member lends it through a view with no release.
 */

const engine = await TightbeamWsClient.init();

describe("realm views", () => {
	it("the zstd, sha3_256, and profile views expose no release", () => {
		expectTypeOf<ZstdView>().not.toHaveProperty("free");
		expectTypeOf<ZstdView>().not.toHaveProperty(Symbol.dispose);
		expectTypeOf<Sha3_256>().not.toHaveProperty("free");
		expectTypeOf<Sha3_256>().not.toHaveProperty(Symbol.dispose);
		expectTypeOf<OidView>().not.toHaveProperty("free");
		expectTypeOf<OidView>().not.toHaveProperty(Symbol.dispose);
		expectTypeOf<ProfileView>().not.toHaveProperty("free");
		expectTypeOf<ProfileView>().not.toHaveProperty(Symbol.dispose);

		const zstd = engine.zstd();
		const hasher = engine.sha3_256;
		const profile = engine.profile;
		expect("free" in zstd).toBe(false);
		expect(Symbol.dispose in zstd).toBe(false);
		expect("free" in hasher).toBe(false);
		expect(Symbol.dispose in hasher).toBe(false);
		expect("free" in hasher.algorithmOid).toBe(false);
		expect(Symbol.dispose in hasher.algorithmOid).toBe(false);
		expect("free" in profile).toBe(false);
		expect(Symbol.dispose in profile).toBe(false);
		expect("free" in profile.data).toBe(false);
		expect(Symbol.dispose in profile.data).toBe(false);
	});
});
