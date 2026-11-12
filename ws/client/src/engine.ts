/**
 * The loaded engine, the owner of every synchronous wasm-backed parse and
 * constructor, as the engine section of `docs/ws-client.md` describes.
 */

import type * as Glue from "#wasm";
import type {
	CleartextConnectOptions,
	CommitmentSalt,
	ConnectOptions,
	DigestInfo,
	MutualConnectOptions,
	MutualIdentity,
	Oid,
	SharedKey,
} from "#wasm";

import { engineLoader } from "#engine";

import type { TransportError } from "./errors.js";
import type { MessageCodec, PayloadCodec } from "./message.js";
import type { OidName, OidView } from "./views.js";
import { FrameBuilder } from "./builder/builder.js";
import { TightbeamWsClient } from "./client.js";
import { Opening } from "./commitment.js";
import {
	Aes256Gcm,
	HpkeDecryptor,
	HpkeEncryptor,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	Sha3_256,
} from "./crypto.js";
import { Envelope } from "./envelope.js";
import { ClientTransportError, TransportErrors } from "./errors.js";
import { Frame } from "./frame.js";
import { Codecs } from "./message.js";
import { Once } from "./once.js";
import { ZstdView } from "./compress.js";
import { ProfileView } from "./views.js";

/**
 * The source the web build loads its binary from: a URL, a `Response`, the
 * bytes, or a compiled `WebAssembly.Module`. The Node build reads its binary
 * beside its glue and ignores it.
 */
export type EngineInput = Glue.InitInput | Promise<Glue.InitInput>;

/**
 * The exports of the glue that both builds share: every class and enum,
 * without the loader of the web build.
 */
export type EngineModule = Omit<typeof Glue, "default" | "initSync">;

/**
 * The loader of one build condition, which imports the glue of that build
 * inside {@link load}.
 */
export interface EngineLoader {
	/**
	 * Import and start the glue of this build once per realm, and answer the
	 * same start to every later call. A failed start leaves the next call to
	 * start again.
	 *
	 * @throws the rejection of the platform or the glue when the binary fails.
	 */
	load(input?: EngineInput): Promise<EngineModule>;
}

/**
 * The key of the brand of the engine parts. The key is module-local, so only
 * an {@link Engine} builds a value of {@link EngineParts}, and a static that
 * takes the parts is reachable through the engine alone.
 */
const PARTS: unique symbol = Symbol("tightbeam engine parts");

/**
 * What the engine lends each class it builds, made once per engine. Each
 * handle is a view that the realm owns, and only an {@link Engine} holds the
 * parts, so a constructor that takes them runs after the load.
 */
export interface EngineParts {
	readonly [PARTS]: true;

	/**
	 * The engine that built the class, which a client answers on `engine`.
	 */
	readonly engine: Engine;

	/**
	 * The loaded module, which each built class calls into.
	 */
	readonly glue: EngineModule;

	/**
	 * The content type `id-data`, which a sealed body takes when nothing names
	 * another.
	 */
	readonly data: OidView;

	/**
	 * The profile hasher, the default of each verdict that a frame judges.
	 */
	readonly sha3_256: Sha3_256;

	/**
	 * The profile zstd at the default ceiling.
	 */
	readonly zstd: ZstdView;
}

/**
 * The loaded engine. Every parse and constructor that calls into the module
 * synchronously is a method of this class, and only {@link Engine.load}
 * builds one, once the module loaded. A realm holds one engine, so every load
 * after the first resolves the same one.
 */
export class Engine {
	/**
	 * The load of the engine of this realm.
	 */
	static readonly #loading = new Once<Engine>();

	/**
	 * The parts this engine lends the classes it builds.
	 */
	readonly #parts: EngineParts;

	/**
	 * The recognizer of the transport errors of this engine.
	 */
	readonly #errors: TransportErrors;

	/**
	 * The object identifiers of the tightbeam profile, which the realm owns.
	 */
	readonly profile: ProfileView;

	/**
	 * The frame protocol versions, valued by their encoded ordinals.
	 */
	readonly Version: EngineModule["Version"];

	/**
	 * The message priorities (V2+), valued by their encoded ordinals.
	 */
	readonly MessagePriority: EngineModule["MessagePriority"];

	/**
	 * The profile codec: raw bytes in the opaque body wrapper.
	 */
	readonly opaque: MessageCodec<Uint8Array>;

	/**
	 * Frame-in-frame payloads: a codec whose messages are full tightbeam
	 * frames, carried untouched inside the body of another frame, so the
	 * security a publisher applied survives the pub/sub broker.
	 */
	readonly framed: MessageCodec<Frame>;

	/**
	 * The profile hasher: SHA3-256, computed in the module, which lends the
	 * realm handle of its algorithm as a view.
	 */
	readonly sha3_256: Sha3_256;

	private constructor(glue: EngineModule) {
		const oids = glue.ProfileOids.read();
		let profile: ProfileView;
		try {
			profile = ProfileView.read(oids);
		} finally {
			oids.free();
		}

		const sha3_256 = Sha3_256.over(glue.Sha3_256, profile.sha3_256);
		const handle = new glue.ZstdCompression();
		const zstd = ZstdView.over(handle, profile.zstd);

		this.#parts = {
			[PARTS]: true,
			engine: this,
			glue,
			data: profile.data,
			sha3_256,
			zstd,
		};
		this.#errors = TransportErrors.over(glue.Codes);
		this.profile = profile;
		this.Version = glue.Version;
		this.MessagePriority = glue.MessagePriority;

		const codecs = Codecs.over(glue);

		this.opaque = codecs.opaque;
		this.framed = codecs.wrapping({
			encode: (inner: Frame): Uint8Array => inner.toDer(),
			decode: (payload: Uint8Array): Frame => this.frame(payload),
		});
		this.sha3_256 = sha3_256;
	}

	/**
	 * Load the WebAssembly engine of this realm under the load rules of
	 * `docs/ws-client.md`, and resolve with the {@link Engine} that proves it.
	 *
	 * @throws TightbeamTransportError `EngineUnavailable` when the binary is
	 * missing or does not start, with the platform failure as its `cause`.
	 */
	static load(input?: EngineInput): Promise<Engine> {
		const loading = Engine.#loading.run(() => Engine.#start(input));
		return loading;
	}

	/**
	 * Start the glue from `input` and build the engine over it, or reject
	 * with `EngineUnavailable`. The loader starts the glue once per realm, and
	 * the memo of {@link load} builds one engine over it.
	 */
	static async #start(input?: EngineInput): Promise<Engine> {
		try {
			const glue = await engineLoader.load(input);
			const engine = new Engine(glue);
			return engine;
		} catch (cause) {
			throw ClientTransportError.engineUnavailable(cause);
		}
	}

	get #glue(): EngineModule {
		return this.#parts.glue;
	}

	/**
	 * Narrow an unknown rejection to a structured {@link TransportError}: an `Error` with the name brand of a transport
	 * error, whose `code` is a code that the engine or the client declares. The check answers `false` for a forged
	 * error that carries the brand and an unknown code.
	 */
	isTransportError(value: unknown): value is TransportError {
		const recognized = this.#errors.recognizes(value);
		return recognized;
	}

	/**
	 * Parse `dotted` as an object identifier, such as `1.2.840.113549.1.7.1`.
	 *
	 * @throws TightbeamTransportError `InvalidOid` when `dotted` is no dotted
	 * object identifier the engine encodes.
	 */
	oid(dotted: string): Oid {
		const oid = this.#glue.Oid.parse(dotted);
		return oid;
	}

	/**
	 * Parse `bytes` as a commitment salt: empty for a plain digest, or at
	 * least 16 octets that hide the body.
	 *
	 * @throws TightbeamTransportError `InvalidSaltLength` when a non-empty
	 * salt is too short to hide the body.
	 */
	salt(bytes: Uint8Array): CommitmentSalt {
		const salt = this.#glue.CommitmentSalt.parse(bytes);
		return salt;
	}

	/**
	 * The digest `digest` that `algorithmOid` produced, such as a received
	 * commitment.
	 *
	 * @throws TightbeamTransportError `EmptyDigest` when `digest` holds no
	 * octets.
	 */
	digestInfo(algorithmOid: OidName, digest: Uint8Array): DigestInfo {
		using named = algorithmOid.clone();

		const info = this.#glue.DigestInfo.of(named, digest);
		return info;
	}

	/**
	 * The profile zstd compression, whose decompression stops at `maxOutput`
	 * octets, 16 MiB by default.
	 *
	 * @throws TightbeamTransportError `InvalidMaxOutput` for a `maxOutput` that
	 * is no whole, non-negative number.
	 */
	zstd(maxOutput?: number): ZstdView {
		if (maxOutput === undefined) {
			return this.#parts.zstd;
		}

		const bound = this.#glue.ZstdCompression.ceiling(maxOutput);
		const zstd = ZstdView.over(bound, this.profile.zstd);
		return zstd;
	}

	/**
	 * Parse a frame DER. The frame keeps its own copy, so a later write to
	 * `der` leaves the frame as it parsed.
	 *
	 * @throws TightbeamTransportError with the engine's code, such as
	 * `SerializationError`, when the bytes are not a well-formed frame.
	 */
	frame(der: Uint8Array): Frame {
		const frame = Frame.decode(this.#parts, der);
		return frame;
	}

	/**
	 * Begin building a frame whose body carries the raw bytes `bytes` under
	 * the profile opaque wrapper.
	 */
	frameBuilder(bytes: Uint8Array): FrameBuilder {
		const builder = FrameBuilder.bytes(this.#parts, bytes);
		return builder;
	}

	/**
	 * Begin building a frame whose body carries `message` under the schema of
	 * `codec`.
	 */
	messageBuilder<T>(codec: MessageCodec<T>, message: T): FrameBuilder {
		const builder = FrameBuilder.message(this.#parts, codec, message);
		return builder;
	}

	/**
	 * A typed message envelope over `codec`, with no layer declared.
	 */
	envelope<T>(codec: MessageCodec<T>): Envelope<T> {
		const envelope = Envelope.over(this.#parts, codec);
		return envelope;
	}

	/**
	 * Lift a payload codec into a {@link MessageCodec} that wraps its bytes in
	 * the profile opaque body.
	 */
	wrapping<T>(inner: PayloadCodec<T>): MessageCodec<T> {
		const codecs = Codecs.over(this.#glue);
		const codec = codecs.wrapping(inner);
		return codec;
	}

	/**
	 * The opening of a commitment over `bodyDer` under `salt`. It copies `bodyDer` and then takes the salt, so `salt`
	 * keeps an empty shell.
	 *
	 * @throws TightbeamTransportError `CommitmentSpent` when the salt moved out of `salt` already.
	 * @throws the refusal of the copy of `bodyDer`, such as for a detached buffer, and `salt` keeps its salt.
	 */
	opening(salt: CommitmentSalt, bodyDer: Uint8Array): Opening {
		const opening = Opening.over(this.#parts, salt, bodyDer);
		return opening;
	}

	/**
	 * Wrap a raw 32-byte secp256k1 scalar.
	 *
	 * @throws TightbeamTransportError `InvalidSigningKey` when the scalar is
	 * not 32 octets, or names no key.
	 */
	signingKey(bytes: Uint8Array): Secp256k1SigningKey {
		const key = Secp256k1SigningKey.fromBytes(this.#parts, bytes);
		return key;
	}

	/**
	 * Wrap a SEC1-encoded point (33-byte compressed or 65-byte uncompressed).
	 *
	 * @throws TightbeamTransportError `InvalidVerifyingKey` when the octets
	 * name no secp256k1 point.
	 */
	verifyingKey(sec1: Uint8Array): Secp256k1VerifyingKey {
		const key = Secp256k1VerifyingKey.fromSec1Bytes(this.#parts, sec1);
		return key;
	}

	/**
	 * Wrap a raw 32-byte shared key and the identifier that names it.
	 *
	 * @throws TightbeamTransportError `EmptyKeyId` at `shared.keyId` when
	 * `keyId` is empty, and `KeyError` at `shared.key` when the key is not 32
	 * octets.
	 */
	aes256Gcm(shared: SharedKey): Aes256Gcm {
		const cipher = Aes256Gcm.fromKey(this.#parts, shared);
		return cipher;
	}

	/**
	 * Wrap the SEC1-encoded public key of a recipient.
	 *
	 * @throws TightbeamTransportError `InvalidVerifyingKey` when the octets
	 * name no secp256k1 point.
	 */
	hpkeEncryptor(recipientPublicKey: Uint8Array): HpkeEncryptor {
		const encryptor = HpkeEncryptor.fromBytes(this.#parts, recipientPublicKey);
		return encryptor;
	}

	/**
	 * Wrap the raw 32-byte secret key of a recipient.
	 *
	 * @throws TightbeamTransportError `InvalidSigningKey` when the secret is
	 * not 32 octets, or names no key.
	 */
	hpkeDecryptor(secretKey: Uint8Array): HpkeDecryptor {
		const decryptor = HpkeDecryptor.fromBytes(this.#parts, secretKey);
		return decryptor;
	}

	/**
	 * Open a server-authenticated multiplexed session to `url` that pins
	 * `serverCertDer`, and resolve once the handshake negotiated multiplexing.
	 *
	 * @throws TightbeamTransportError, as a rejection, for a url, certificate, option, or dial fault that the
	 * connectors section of `docs/ws-client.md` lists. An abort rejects with the reason of the signal.
	 */
	connect(url: string, serverCertDer: Uint8Array, options?: ConnectOptions): Promise<TightbeamWsClient> {
		const parts = this.#parts;
		const client = TightbeamWsClient.connect(parts, url, serverCertDer, options);
		return client;
	}

	/**
	 * As {@link connect}, and present a client identity whose key is the raw
	 * 32-byte secp256k1 scalar or an external `TransportSigner`.
	 *
	 * @throws TightbeamTransportError, as a rejection, for a url, identity, option, or dial fault that the connectors
	 * section of `docs/ws-client.md` lists. An abort rejects as {@link connect} states.
	 */
	connectMutual(url: string, identity: MutualIdentity, options?: MutualConnectOptions): Promise<TightbeamWsClient> {
		const parts = this.#parts;
		const client = TightbeamWsClient.connectMutual(parts, url, identity, options);
		return client;
	}

	/**
	 * Open a cleartext multiplexed session to `url`, which resolves once the socket is open and carries NO
	 * confidentiality or integrity protection. Both endpoints MUST configure the same symmetric stream cap.
	 *
	 * @throws TightbeamTransportError, as a rejection, for a url, option, or dial fault that the connectors section of
	 * `docs/ws-client.md` lists. An abort rejects as {@link connect} states.
	 */
	connectCleartext(url: string, options?: CleartextConnectOptions): Promise<TightbeamWsClient> {
		const parts = this.#parts;
		const client = TightbeamWsClient.connectCleartext(parts, url, options);
		return client;
	}
}
