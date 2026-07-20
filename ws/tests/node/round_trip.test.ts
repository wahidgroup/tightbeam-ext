import { describe, expect, it } from "vitest";

import type { Frame } from "@wahidgroup/tightbeam-ws-client";
import {
	Aes256Gcm,
	EciesDecryptor,
	EciesEncryptor,
	PROFILE_OIDS,
	Secp256k1SigningKey,
	Sha3_256,
	TightbeamWsClient,
	TightbeamWsSecureClient,
	frame,
} from "@wahidgroup/tightbeam-ws-client";

import { certBytes, secureEndpoint, sinkEndpoint, wsEndpoint } from "../env.js";

/**
 * The emit surface shared by the cleartext and encrypted clients.
 */
interface EmitClient {
	emit(frame: Frame): Promise<Frame | undefined>;
}

/**
 * Open a client via `connect`, run the test body, and always release the
 * socket.
 */
async function withClient<TClient extends { close(): void }>(
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
 * Open a cleartext client against the echo server.
 */
async function withEchoClient(
	run: (client: TightbeamWsClient) => Promise<void>,
): Promise<void> {
	await withClient(() => TightbeamWsClient.connect(wsEndpoint), run);
}

/**
 * Emit `built` and return the response frame; a missing response fails the
 * round-trip.
 */
async function emitOrFail(client: EmitClient, built: Frame): Promise<Frame> {
	const response = await client.emit(built);
	if (response === undefined) {
		throw new Error("the peer returned no response frame");
	}

	return response;
}

const TEXT = new TextDecoder();
const BODY = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
const SIGNING_KEY = Secp256k1SigningKey.fromBytes(new Uint8Array(32).fill(3));
const SALT = new Uint8Array([0x5a, 0x5a]);

describe("Node round-trips against the dockerized echo server", () => {
	it("round-trips a cleartext frame over Node's global WebSocket", async () => {
		await withEchoClient(async (client) => {
			const built = await frame(BODY)
				.withId("node-e2e")
				.withOrder(3)
				.build();

			const response = await emitOrFail(client, built);
			expect(response.body).toEqual(BODY);
			expect(TEXT.decode(response.id)).toBe("node-e2e");
			expect(response.order).toBe(3n);
		});
	});

	it("verifies a signed, committed frame after the echo", async () => {
		await withEchoClient(async (client) => {
			const built = await frame(BODY)
				.withId("node-signed")
				.withOrder(4)
				.withMessageHasher(new Sha3_256(), SALT)
				.withWitnessHasher(new Sha3_256())
				.withSigner(SIGNING_KEY)
				.build();

			const response = await emitOrFail(client, built);
			expect(response.signed).toBe(true);

			response.verify(SIGNING_KEY.verifyingKey());

			await expect(response.frameIntegrityVerdict()).resolves.toBe(
				"verified",
			);
			await expect(response.messageCommitmentVerdict(SALT)).resolves.toBe(
				"verified",
			);
		});
	});

	it("round-trips an AES-256-GCM sealed body and opens it with the key", async () => {
		const cipher = Aes256Gcm.fromKey(new Uint8Array(32).fill(7));

		await withEchoClient(async (client) => {
			const built = await frame(BODY)
				.withId("node-aead")
				.withOrder(6)
				.withEncryptor(cipher)
				.build();

			const response = await emitOrFail(client, built);
			expect(response.confidential).toBe(true);
			expect(response.confidentialityInfo?.algorithmOid).toBe(
				PROFILE_OIDS.aes256Gcm,
			);
			expect(response.body).not.toEqual(BODY);
			await expect(response.decryptBytes(cipher)).resolves.toEqual(BODY);
		});
	});

	it("seals a body to a recipient with ECIES and opens it with the secret", async () => {
		const recipientSecret = new Uint8Array(32).fill(3);
		const recipientPublic = SIGNING_KEY.verifyingKey().toSec1Bytes();

		await withEchoClient(async (client) => {
			const built = await frame(BODY)
				.withId("node-ecies")
				.withOrder(8)
				.withEncryptor(EciesEncryptor.fromBytes(recipientPublic))
				.build();

			const response = await emitOrFail(client, built);
			expect(response.confidential).toBe(true);
			expect(response.body).not.toEqual(BODY);

			const decryptor = EciesDecryptor.fromBytes(recipientSecret);
			await expect(response.decryptBytes(decryptor)).resolves.toEqual(
				BODY,
			);
		});
	});

	it("resolves undefined when the server accepts without a response frame", async () => {
		await withClient(
			() => TightbeamWsClient.connect(sinkEndpoint),
			async (client) => {
				const built = await frame(BODY)
					.withId("node-sink")
					.withOrder(10)
					.build();

				const response = await client.emit(built);
				expect(response).toBeUndefined();
			},
		);
	});

	it("round-trips over an ECIES-encrypted session", async () => {
		const serverCert = certBytes("server.cert.der");

		await withClient(
			() => TightbeamWsSecureClient.connect(secureEndpoint, serverCert),
			async (client) => {
				const built = await frame(BODY)
					.withId("node-secure")
					.withOrder(9)
					.build();

				const response = await emitOrFail(client, built);
				expect(response.body).toEqual(BODY);
				expect(TEXT.decode(response.id)).toBe("node-secure");
			},
		);
	});
});
