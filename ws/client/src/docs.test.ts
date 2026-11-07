import { describe, expectTypeOf, it } from "vitest";

import { sha3_512 } from "@noble/hashes/sha3.js";

import type {
	Aes256Gcm,
	BodyCompressor,
	BodyInflator,
	CompressedBody,
	Engine,
	Envelope,
	Frame,
	Hasher,
	MessageCodec,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	Signatory,
	SocketCloseInfo,
	TransportError,
	TransportSigner,
} from "./index.js";
import { Route, Router, TightbeamWsClient } from "./index.js";

/**
 * Every TypeScript sample of `docs/ws-client.md`, one case per sample, named
 * by its section. Each case holds its sample verbatim inside a function that
 * the case never calls: `tsc` compiles every sample under the typecheck of
 * the suite, and a sample that drifts from the API fails the typecheck. The
 * names each sample takes from its surroundings are declared below, typed as
 * the page reads them.
 */

interface ChatMessage {
	author: string;
	text: string;
}

interface Tick {
	price: number;
}

interface Note {
	author: string;
	text: string;
}

declare const engine: Engine;
declare const wasmUrl: URL;
declare const compiledModule: WebAssembly.Module;
declare const url: string;
declare const serverCertDer: Uint8Array;
declare const clientCertDer: Uint8Array;
declare const clientSigningKey: Uint8Array;
declare const spkiFromKeyStore: Uint8Array;
declare const keyStore: {
	signDigest(prehash: Uint8Array): Promise<Uint8Array>;
};
declare function paymentFor(
	challenge: Uint8Array | undefined,
): Uint8Array | undefined;
declare function handle(value: Uint8Array): Uint8Array;
declare const builtFirst: Frame;
declare const builtSecond: Frame;
declare const client: TightbeamWsClient;
declare const frameDer: Uint8Array;
declare const mid: number;
declare const chunkA: Uint8Array;
declare const chunkB: Uint8Array;
declare const ChatCodec: MessageCodec<ChatMessage>;
declare const TickCodec: MessageCodec<Tick>;
declare const publisherKey: Secp256k1VerifyingKey;
declare const store: {
	applyTick(tick: Tick): void;
	appendChat(message: ChatMessage): void;
};
declare function buildReceipt(request: Frame): Promise<Frame>;
declare const mux: TightbeamWsClient;
declare const payload: Uint8Array;
declare const signingKey: Secp256k1SigningKey;
declare const target: string;
declare const work: Frame;
declare const signal: AbortSignal;
declare function handleRefusal(error: TransportError): void;
declare const built: Frame;
declare function scheduleReconnect(code: number): void;
declare const routes: Router;
declare function sleep(milliseconds: number): Promise<void>;
declare function report(info: SocketCloseInfo): void;
declare const rawScalar: Uint8Array;
declare const body: Uint8Array;
declare const digestOid: string;
declare const digest: Uint8Array;
declare const salt: Uint8Array;
declare const key: Uint8Array;
declare const keyId: Uint8Array;
declare const walletKeyId: Uint8Array;
declare const wallet: {
	signDigest(prehash: Uint8Array): Promise<Uint8Array>;
};
declare const received: Frame;
declare const sealed: Frame;
declare const cipher: Aes256Gcm;
declare const response: Frame;
declare const sha3_512Hasher: Hasher;
declare const recipientSecretKey: Uint8Array;
declare const Chat: MessageCodec<ChatMessage>;
declare const Notes: MessageCodec<Note>;
declare const topicKey: Uint8Array;
declare const topicKeyId: Uint8Array;
declare const note: Note;
declare const relayed: Frame;
declare const recipientSecret: Uint8Array;
declare const bodyDer: Uint8Array;

describe("docs/ws-client.md", () => {
	it("Engine", () => {
		async function sample(): Promise<void> {
			// Node, or a page that serves the binary beside the glue:
			const engine = await TightbeamWsClient.init();

			// A custom host, a CSP-restricted page, or a worker with a compiled module:
			const hosted = await TightbeamWsClient.init(wasmUrl);
			const inWorker = await TightbeamWsClient.init(compiledModule);
			expectTypeOf([engine, hosted, inWorker]).toEqualTypeOf<Engine[]>();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Connectors", () => {
		async function sample(): Promise<void> {
			// Server-authenticated:
			const secure = await engine.connect(url, serverCertDer);
			// Mutually authenticated (32-byte secp256k1 signing key):
			const mutual = await engine.connectMutual(url, {
				serverCertDer,
				clientCertDer,
				clientKey: clientSigningKey,
			});
			expectTypeOf([secure, mutual]).toBeArray();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Connectors, external signers", () => {
		async function sample(): Promise<void> {
			const signer: TransportSigner = {
				algorithmOid: "2.16.840.1.101.3.4.3.10", // ecdsa-with-SHA3-256
				publicKeyDer: spkiFromKeyStore,
				signPrehash: (prehash) => keyStore.signDigest(prehash),
			};

			const external = await engine.connectMutual(url, {
				serverCertDer,
				clientCertDer,
				clientKey: signer,
			});
			expectTypeOf(external).toEqualTypeOf<TightbeamWsClient>();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Connectors, session budgets", () => {
		async function sample(): Promise<void> {
			const metered = await engine.connectMutual(
				url,
				{ serverCertDer, clientCertDer, clientKey: clientSigningKey },
				{
					budgets: { clientToServer: 4096, serverToClient: 4096 },
					approveReceipt: ({ receiptDer, challenge }) => {
						// Pay the invoice in `challenge`, or return undefined to refuse.
						expectTypeOf(receiptDer).toEqualTypeOf<Uint8Array>();
						return paymentFor(challenge);
					},
				},
			);

			// eslint-disable-next-line @typescript-eslint/no-unused-expressions -- the docs sample, verbatim
			metered.usableSendBudget; // epoch usable credits, or undefined when unmetered
			// eslint-disable-next-line @typescript-eslint/no-unused-expressions -- the docs sample, verbatim
			metered.sessionReceiptDer; // dual-signed receipt DER, rotates on renewal
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Streams", () => {
		async function sample(): Promise<void> {
			const mux = await engine.connect(url, serverCertDer);

			// Answer server-initiated streams. Callable repeatedly (the latest
			// handler serves streams dispatched after the call), and handlers for
			// distinct streams run concurrently.
			mux.serve(async (request) => {
				const reply = await engine
					.frameBuilder(handle(request.message(engine.opaque)))
					.withId("reply")
					.withOrder(1)
					.build();
				return reply; // or undefined/null for a bodiless acceptance
			});

			// Concurrent client-initiated streams over the one connection.
			const [first, second] = await Promise.all([
				mux.emit(builtFirst),
				mux.emit(builtSecond),
			]);

			await mux.shutdown(); // GoAway, drain in-flight streams, stop
			await mux.close();

			expectTypeOf([first, second]).toBeArray();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Streams, progressive bodies", () => {
		async function sample(): Promise<void> {
			await using stream = client.openStream();
			await stream.push(frameDer.subarray(0, mid));
			const response = await stream.closeWith(frameDer.subarray(mid));

			await using duplex = client.openDuplex();
			await duplex.push(chunkA);

			const first = await duplex.body[Symbol.asyncIterator]().next();
			await duplex.closeWith(chunkB);
			for await (const chunk of duplex.body) {
				handle(chunk);
			}

			expectTypeOf([response, first]).toBeArray();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Streams, routing", () => {
		function sample(): void {
			const chat = engine.envelope(ChatCodec).verified(publisherKey);
			const routes = new Router({
				"tick/": Route.of(TickCodec, (tick) => {
					store.applyTick(tick); // tick: Tick, inferred from the codec
					return undefined; // bodiless ack
				}),
				"chat/": Route.sealed(chat, async (message, request) => {
					store.appendChat(message); // the signature verified before decode
					return buildReceipt(request); // response frame
				}),
			});

			mux.serve((request) => routes.dispatch(request));
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Cluster work submission", () => {
		async function sample(): Promise<void> {
			const work = await engine
				.frameBuilder(payload)
				.withId("job-42")
				.withOrder(1)
				.withSigner(signingKey)
				.build();

			const served = await mux.submitWork(
				"urn:tightbeam::servlet:work-probe",
				work,
			);
			served.verify(signingKey.verifyingKey());
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Cluster work submission, refusal", () => {
		async function sample(): Promise<void> {
			try {
				await mux.submitWork(target, work, { signal });
			} catch (error) {
				if (
					engine.isTransportError(error) &&
					error.code === "WorkRefused"
				) {
					handleRefusal(error);
				}
			}
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Cancellation", () => {
		async function sample(): Promise<void> {
			const response = await mux.emit(built, {
				signal: AbortSignal.timeout(5_000),
			});

			expectTypeOf(response).toEqualTypeOf<Frame | undefined>();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Cancellation of a connector", () => {
		async function sample(): Promise<void> {
			const mux = await engine.connect(url, serverCertDer, {
				signal: AbortSignal.timeout(5_000),
			});

			expectTypeOf(mux).toEqualTypeOf<TightbeamWsClient>();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Connection lifecycle", () => {
		function sample(): void {
			async function watchClose(
				client: TightbeamWsClient,
			): Promise<void> {
				const info = await client.closed;
				if (!info.wasClean) {
					scheduleReconnect(info.code);
				}
			}

			void watchClose(client);
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Connection lifecycle, lifetime", () => {
		async function sample(): Promise<void> {
			await using client = await engine.connectCleartext(url);
			client.serve((request) => routes.dispatch(request));
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Connection lifecycle, reconnection", () => {
		async function connectLoop(
			handle: (client: TightbeamWsClient) => void,
		): Promise<void> {
			let delay = 500;

			for (;;) {
				let client: TightbeamWsClient;
				try {
					client = await engine.connect(url, serverCertDer, {
						signal: AbortSignal.timeout(5_000),
					});
				} catch {
					await sleep((delay = Math.min(delay * 2, 30_000)));
					continue;
				}

				delay = 500;

				/*
				 * serve is per connection: re-register handlers here.
				 */
				handle(client);

				const info = await client.closed;

				/*
				 * Free the dead connection's wasm resources. The GoAway getters
				 * stay readable from the close snapshot.
				 */
				await client.close();

				switch (client.goawayReason) {
					case "shutdown":
						break; // orderly drain (rotation, redeploy): go right back
					case "enhance-your-calm":
						await sleep((delay = Math.min(delay * 2, 30_000)));
						break; // the server asked for calm
					case "protocol-error":
						report(info);
						return; // a bug, not a transient fault
					default:
						await sleep(delay); // no GoAway: connection loss
				}
			}
		}

		expectTypeOf(connectLoop).toBeFunction();
	});

	it("Transport errors", () => {
		async function sample(): Promise<void> {
			try {
				await mux.emit(built);
			} catch (error) {
				if (
					engine.isTransportError(error) &&
					error.code === "Draining"
				) {
					// GoAway received on a live connection: reconnect before emitting again.
				}
			}
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Transport errors, stream slot", () => {
		async function sample(): Promise<void> {
			await mux.waitForStreamSlot({ signal: AbortSignal.timeout(5_000) });

			const response = await mux.emit(built);
			expectTypeOf(response).toEqualTypeOf<Frame | undefined>();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Keepalive", () => {
		async function sample(): Promise<void> {
			await mux.ping({ signal: AbortSignal.timeout(5_000) });
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Frame builder", () => {
		async function sample(): Promise<void> {
			const signingKey = engine.signingKey(rawScalar);
			const built = await engine
				.frameBuilder(body)
				.withId("doc-42")
				.withOrder(1n)
				.withPriority(engine.MessagePriority.LowLatency) // V2+
				.withLifetime(60) // V2+
				.withPreviousHash(
					engine.digestInfo(engine.oid(digestOid), digest),
				) // V2+
				.withMatrix(2, new Uint8Array([0, 1, 1, 0])) // V3+
				.withMessageHasher(engine.sha3_256) // V1+: body commitment
				.withCommitment(engine.salt(salt)) // hide the commitment behind a salt of 16+ octets
				.withWitnessHasher(engine.sha3_256) // V1+: frame integrity
				.withEncryptor(engine.aes256Gcm({ key, keyId })) // V1+: body encryption
				.withSigner(signingKey) // V1+: secp256k1 signature
				.assertVersion(engine.Version.V3) // fail the build unless it lands on V3
				.build();

			expectTypeOf(built).toEqualTypeOf<Frame>();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Typed messages", () => {
		async function sample(): Promise<void> {
			interface ChatMessage {
				author: string;
				text: string;
			}

			const Chat: MessageCodec<ChatMessage> = engine.wrapping({
				encode: (message) =>
					new TextEncoder().encode(JSON.stringify(message)),
				decode: (payload) => {
					const parsed = JSON.parse(
						new TextDecoder().decode(payload),
					);
					// Runtime validation is the codec's responsibility.
					if (
						typeof parsed?.author !== "string" ||
						typeof parsed?.text !== "string"
					) {
						throw new Error("not a ChatMessage");
					}

					return parsed;
				},
			});

			const built = await engine
				.frameBuilder()
				.withMessage(Chat, { author: "ada", text: "hello" })
				.build();

			const reply = await client.emit(built);
			const message = reply?.message(Chat); // ChatMessage
			expectTypeOf(message).toEqualTypeOf<ChatMessage | undefined>();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Custom cryptography", () => {
		async function sample(): Promise<void> {
			// Any digest: implement Hasher with the OID peers should recompute under.
			const sha3_512Hasher: Hasher = {
				algorithmOid: engine.oid("2.16.840.1.101.3.4.2.10"),
				digest: async (data) => sha3_512(data),
			};

			// Any signer of the profile signature: the builder hands the implementation
			// the digest of the frame's CMS signed attributes and attaches the returned
			// DER signature, so an external signer's private key never enters wasm memory
			// (wallets, passkeys, HSMs, remote KMS).
			const walletSigner: Signatory = {
				signerId: () => walletKeyId, // subject key identifier of its certificate
				signPrehash: async (prehash) => wallet.signDigest(prehash),
			};

			const built = await engine
				.frameBuilder(body)
				.withWitnessHasher(sha3_512Hasher)
				.withSigner(walletSigner)
				.build();
			expectTypeOf(built).toEqualTypeOf<Frame>();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Compression", () => {
		async function sample(): Promise<void> {
			const zstd = engine.zstd();
			const built = await engine
				.frameBuilder(body)
				.withCompressor(zstd)
				.build();

			// Cleartext + compressed: the engine inflates on the path a native peer takes.
			const message = await received.inflateMessage(zstd, engine.opaque);
			// Compressed then sealed: name both capabilities.
			const opened = await sealed.open(engine.opaque, {
				opener: cipher,
				inflator: zstd,
			});

			expectTypeOf([built, message, opened]).toBeArray();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Compression over zlib", () => {
		async function sample(): Promise<void> {
			async function pump(
				transform: ReadableWritablePair<Uint8Array, BufferSource>,
				bytes: Uint8Array,
			): Promise<Uint8Array> {
				const source = new Blob([bytes.slice()])
					.stream()
					.pipeThrough(transform);
				return new Uint8Array(await new Response(source).arrayBuffer());
			}

			const zlibOid = engine.profile.zlib;
			const zlib: BodyCompressor & BodyInflator = {
				algorithmOid: zlibOid,
				compress: async (bodyDer) => ({
					data: await pump(new CompressionStream("deflate"), bodyDer),
				}),
				admitsParameters: (parametersDer) =>
					parametersDer === undefined,
				decompress: (data) =>
					pump(new DecompressionStream("deflate"), data),
			};

			const built = await engine
				.frameBuilder(body)
				.withCompressor(zlib)
				.build();
			expectTypeOf(built).toEqualTypeOf<Frame>();
			expectTypeOf<CompressedBody>().toHaveProperty("data");
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Verification and decryption", () => {
		async function sample(): Promise<void> {
			response.verify(signingKey.verifyingKey()); // profile scheme: throws when invalid
			await response.frameIntegrityVerdict(); // "verified" | "absent" | ...
			await response.frameIntegrityVerdict(sha3_512Hasher); // under your own hasher
			await response.messageCommitmentVerdict(engine.salt(salt)); // checks the body commitment

			// Open an encrypted body with the matching cipher or recipient secret,
			// decoding the plaintext under any codec (engine.opaque for raw bytes):
			await response.open(engine.opaque, {
				opener: engine.aes256Gcm({ key, keyId }),
			});
			await response.open(Chat, {
				opener: engine.hpkeDecryptor(recipientSecretKey),
			});

			// Raw surfaces for external verification:
			response.tbs(); // to-be-signed bytes
			response.signaturePrehash(); // digest the signature verifies over
			response.witnessInput(); // frame-integrity preimage
			// eslint-disable-next-line @typescript-eslint/no-unused-expressions -- the docs sample, verbatim
			response.signatureInfo; // { algorithmOid, digestAlgorithmOid, signature }
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Envelopes", () => {
		async function sample(): Promise<void> {
			const notes = engine
				.envelope(Notes) // any MessageCodec<T>
				.signed(signingKey)
				.sealed(engine.aes256Gcm({ key: topicKey, keyId: topicKeyId }))
				.compressed(engine.zstd());

			// Sender: the layers are already applied, the metadata stays yours.
			const sent = await notes
				.frame(note)
				.withId("note-1")
				.withOrder(1n)
				.build();

			// Receiver: a Note, or a rejection.
			const received = await notes.unwrap(relayed);
			expectTypeOf(sent).toEqualTypeOf<Frame>();
			expectTypeOf(received).toEqualTypeOf<Note>();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Envelopes of one-sided parties", () => {
		function sample(): void {
			// A subscriber that verifies and opens, but never signs or sends.
			const readOnly = engine
				.envelope(Notes)
				.verified(publisherKey)
				.sealed(engine.hpkeDecryptor(recipientSecret));
			expectTypeOf(readOnly).toEqualTypeOf<Envelope<Note>>();
		}

		expectTypeOf(sample).toBeFunction();
	});

	it("Detached commitments", () => {
		async function sample(): Promise<void> {
			// Prover: publish `commitment`, keep the salt and the body secret until disclosure.
			const secret = crypto.getRandomValues(new Uint8Array(32)); // a high-entropy salt hides the body
			using proving = engine.opening(engine.salt(secret), bodyDer);
			const commitment = await proving.commit(engine.sha3_256);

			// Verifier: reassemble the disclosed salt and body, and check in constant time.
			using disclosed = engine.opening(engine.salt(secret), bodyDer);
			const verified = await disclosed.verify(
				engine.sha3_256,
				commitment,
			);
			expectTypeOf(verified).toEqualTypeOf<boolean>();
		}

		expectTypeOf(sample).toBeFunction();
	});
});
