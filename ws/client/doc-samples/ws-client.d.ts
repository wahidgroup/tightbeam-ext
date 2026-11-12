/**
 * The names that the samples of `docs/ws-client.md` take from their
 * surroundings, as `src/docs.test.ts` compiles them.
 */
import type {
	Aes256Gcm,
	Engine,
	Frame,
	Hasher,
	MessageCodec,
	Router,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	SocketCloseInfo,
	TightbeamWsClient as Client,
	TransportError,
} from "@wahidgroup/tightbeam-ws-client";

declare global {
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

	type TightbeamWsClient = Client;

	const engine: Engine;
	const wasmUrl: URL;
	const compiledModule: WebAssembly.Module;
	const url: string;
	const serverCertDer: Uint8Array;
	const clientCertDer: Uint8Array;
	const clientSigningKey: Uint8Array;
	const spkiFromKeyStore: Uint8Array;
	const keyStore: {
		signDigest(prehash: Uint8Array): Promise<Uint8Array>;
	};
	function paymentFor(challenge: Uint8Array | undefined): Uint8Array | undefined;
	function handle(value: Uint8Array): Uint8Array;
	const builtFirst: Frame;
	const builtSecond: Frame;
	const client: Client;
	const frameDer: Uint8Array;
	const mid: number;
	const chunkA: Uint8Array;
	const chunkB: Uint8Array;
	const ChatCodec: MessageCodec<ChatMessage>;
	const TickCodec: MessageCodec<Tick>;
	const publisherKey: Secp256k1VerifyingKey;
	const store: {
		applyTick(tick: Tick): void;
		appendChat(message: ChatMessage): void;
	};
	function buildReceipt(request: Frame): Promise<Frame>;
	const mux: Client;
	const payload: Uint8Array;
	const signingKey: Secp256k1SigningKey;
	const target: string;
	const work: Frame;
	const signal: AbortSignal;
	function handleRefusal(error: TransportError): void;
	const built: Frame;
	function scheduleReconnect(code: number): void;
	const routes: Router;
	function sleep(milliseconds: number): Promise<void>;
	function report(info: SocketCloseInfo): void;
	const rawScalar: Uint8Array;
	const body: Uint8Array;
	const digestOid: string;
	const digest: Uint8Array;
	const salt: Uint8Array;
	const key: Uint8Array;
	const keyId: Uint8Array;
	const walletKeyId: Uint8Array;
	const wallet: {
		signDigest(prehash: Uint8Array): Promise<Uint8Array>;
	};
	const received: Frame;
	const sealed: Frame;
	const cipher: Aes256Gcm;
	const response: Frame;
	const sha3_512Hasher: Hasher;
	const recipientSecretKey: Uint8Array;
	const Chat: MessageCodec<ChatMessage>;
	const Notes: MessageCodec<Note>;
	const topicKey: Uint8Array;
	const topicKeyId: Uint8Array;
	const note: Note;
	const relayed: Frame;
	const recipientSecret: Uint8Array;
	const bodyDer: Uint8Array;
}
