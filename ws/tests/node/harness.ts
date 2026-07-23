/**
 * Shared helpers for the Node e2e lane: client lifecycle and emit
 * helpers used by every round-trip suite.
 */

import type { Frame } from "@wahidgroup/tightbeam-ws-client";

/**
 * The emit surface shared by the cleartext, encrypted, and multiplexed
 * clients.
 */
export interface EmitClient {
	emit(frame: Frame): Promise<Frame | undefined>;
}

/**
 * Open a client via `connect`, run the test body, and always release the
 * socket.
 */
export async function withClient<TClient extends { close(): void }>(
	connect: () => Promise<TClient>,
	run: (client: TClient) => Promise<void>,
): Promise<void> {
	const client = await connect();
	try {
		await run(client);
	} finally {
		client.close();
	}
}

/**
 * Emit `built` and return the response frame. A missing response fails the
 * round-trip.
 */
export async function emitOrFail(
	client: EmitClient,
	built: Frame,
): Promise<Frame> {
	const response = await client.emit(built);
	if (response === undefined) {
		throw new Error("the peer returned no response frame");
	}

	return response;
}
