/**
 * The facts of the compose stack that the ws suites run against, shared by
 * the Playwright specs and the Node vitest lane.
 */

import { ENVIRONMENT, Identities } from "./env.js";
import { DialFacts } from "./fixtures.js";

/**
 * Every stack fact of the ws suites, read once at load from the environment
 * that `scripts/test-e2e.sh` exports, so a missing or malformed fact throws
 * there.
 */
export const STACK = {
	/**
	 * The multiplexed encrypted echo server: serves concurrent streams, and
	 * runs the command a frame id selects in place of the echo, as
	 * `docs/ws.md` (Demo servers) lists them.
	 */
	muxEndpoint: ENVIRONMENT.text("ECHO_WS_MUX_ENDPOINT"),

	/**
	 * The multiplexed cleartext echo server: same behavior as the encrypted
	 * one, with the stream cap of the stack on both ends in place of
	 * negotiation.
	 */
	muxClearEndpoint: ENVIRONMENT.text("ECHO_WS_MUX_CLEAR_ENDPOINT"),

	/**
	 * The mutually-authenticated multiplexed encrypted echo server: the
	 * encrypted one, which also requires the pinned client certificate and
	 * the demo session-budget paywall.
	 */
	muxMutualEndpoint: ENVIRONMENT.text("ECHO_WS_MUX_MUTUAL_ENDPOINT"),

	/**
	 * Cleartext duplex body echo (`TBWS_ECHO_BODY=duplex`) for `openDuplex`.
	 */
	muxDuplexEndpoint: ENVIRONMENT.text("ECHO_WS_MUX_DUPLEX_ENDPOINT"),

	/**
	 * The cluster work-plane gateway: a real gateway, hive, and probe servlet
	 * in one container, admitting browser work submissions.
	 */
	workGatewayEndpoint: ENVIRONMENT.text("WORK_GATEWAY_WS_ENDPOINT"),

	/**
	 * The servlet type that the work gateway serves its probe under.
	 */
	workServlet: ENVIRONMENT.text("TBWS_WORK_SERVLET"),

	/**
	 * The stream cap that every cleartext dial passes, and the demo paywall
	 * of the mutual echo server.
	 */
	dial: DialFacts.read(ENVIRONMENT),

	/**
	 * The DER certificate that the encrypted servers present, which a dial
	 * pins.
	 */
	serverCertDer: Identities.stack.bytes("server.cert.der"),
} as const;
