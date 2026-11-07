/**
 * The facts of the compose stack that the ws suites run against, shared by
 * the Playwright specs and the Node vitest lane.
 */

import { requireEnv } from "./env.js";
import { readDialFacts } from "./fixtures.js";

/**
 * Every stack fact of the ws suites, read once from the environment that
 * `scripts/test-e2e.sh` exports, under the name the stack writes it. Each
 * value has its one home in a `scripts/stack-env.sh`, and a missing or
 * malformed value throws at load.
 */
export const STACK = {
	/**
	 * The multiplexed encrypted echo server: serves concurrent streams, and
	 * runs the command a frame id selects (`tightbeam_ws::testing::EchoCommand`)
	 * in place of the echo.
	 */
	muxEndpoint: requireEnv("ECHO_WS_MUX_ENDPOINT"),

	/**
	 * The multiplexed cleartext echo server: same behavior as the encrypted
	 * one, with the stream cap of the stack on both ends in place of
	 * negotiation.
	 */
	muxClearEndpoint: requireEnv("ECHO_WS_MUX_CLEAR_ENDPOINT"),

	/**
	 * The mutually-authenticated multiplexed encrypted echo server: the
	 * encrypted one, which also requires the pinned client certificate and
	 * the demo session-budget paywall.
	 */
	muxMutualEndpoint: requireEnv("ECHO_WS_MUX_MUTUAL_ENDPOINT"),

	/**
	 * Cleartext duplex body echo (`TBWS_ECHO_BODY=duplex`) for `openDuplex`.
	 */
	muxDuplexEndpoint: requireEnv("ECHO_WS_MUX_DUPLEX_ENDPOINT"),

	/**
	 * The cluster work-plane gateway: a real gateway, hive, and `work-probe`
	 * servlet in one container, admitting browser work submissions.
	 */
	workGatewayEndpoint: requireEnv("WORK_GATEWAY_WS_ENDPOINT"),

	/**
	 * The stream cap that every cleartext dial passes, and the demo paywall
	 * of the mutual echo server.
	 */
	...readDialFacts(requireEnv),
} as const;
