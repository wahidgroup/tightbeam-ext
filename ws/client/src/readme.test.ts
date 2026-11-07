import { describe, expectTypeOf, it } from "vitest";

import { TightbeamWsClient } from "./index.js";

/**
 * The TypeScript sample of the package README, one case per section. Each
 * case holds its sample verbatim inside a function that the case never calls:
 * `tsc` compiles every sample under the typecheck of the suite, and a sample
 * that drifts from the API fails the typecheck. The samples of
 * `docs/ws-client.md` compile in `docs.test.ts`.
 */
describe("README samples", () => {
	it("quick start", () => {
		async function sample(): Promise<void> {
			const engine = await TightbeamWsClient.init();
			const client = await engine.connectCleartext("ws://localhost:9101");

			const built = await engine
				.frameBuilder(new TextEncoder().encode("hello"))
				.withId("greeting")
				.withOrder(Math.floor(Date.now() / 1000))
				.build();

			const response = await client.emit(built);
			const message = response?.message(engine.opaque);
			console.log(message, response?.order, response?.signed);

			await client.close();
		}

		expectTypeOf(sample).toBeFunction();
	});
});
