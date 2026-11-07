/**
 * The loaded engine: the one proof that the WebAssembly module loaded, and
 * the owner of every synchronous wasm-backed parse and constructor.
 *
 * {@link Engine.load}, which `TightbeamWsClient.init` delegates to, is the
 * one way to make an {@link Engine}, so a call that needs the module before
 * it loaded does not type-check. The glue of each build loads through its own
 * {@link EngineLoader}, which imports it inside `load`, so an import of the
 * package never loads the glue.
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
	ZstdCompression,
} from "#wasm";

import { engineLoader } from "#engine";

import type { TransportError } from "./errors.js";
import type { MessageCodec, PayloadCodec } from "./message.js";
import type { OidName, OidView } from "./views.js";
import { FrameBuilder } from "./builder/builder.js";
import { OVER, TightbeamWsClient } from "./client.js";
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
import { BRANDED_CODE, ClientTransportError, DECIDES } from "./errors.js";
import { Frame } from "./frame.js";
import { Codecs } from "./message.js";
import { ZstdView } from "./compress.js";
import { Lent, ProfileView } from "./views.js";

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
	 * Import and start the glue of this build.
	 *
	 * @throws whatever the platform or the glue rejects with when the binary
	 * is missing or does not start.
	 */
	load(input?: EngineInput): Promise<EngineModule>;
}

/**
 * What the engine lends each class it builds, made once per engine and owned
 * by the realm: the glue of the loaded module, the content type `id-data`
 * that a sealed body takes when nothing names another, the profile hasher,
 * and the profile zstd at the default ceiling. Each handle is lent as a
 * view, so no class it reaches can release it.
 */
export interface EngineParts {
	readonly glue: EngineModule;
	readonly data: OidView;
	readonly sha3_256: Sha3_256;
	readonly zstd: ZstdView;
}

/**
 * The loaded engine.
 *
 * Every parse and constructor that calls into the module synchronously is a
 * method of this class, and only {@link Engine.load} builds one, once the
 * module loaded. A realm holds one engine, so every load after the first
 * resolves the same one.
 */
export class Engine {
	/**
	 * The load in flight, or the engine it made. A failed load clears it, so
	 * a later load starts again.
	 */
	static #loading: Promise<Engine> | undefined;

	/**
	 * The parts this engine lends the classes it builds.
	 */
	readonly #parts: EngineParts;

	/**
	 * The one zstd handle of the realm, which every `ZstdView` reaches.
	 */
	readonly #zstd: ZstdCompression;

	/**
	 * The object identifiers of the tightbeam profile, which the realm owns.
	 */
	readonly profile: ProfileView;

	/**
	 * The frame protocol versions, valued by their wire ordinals.
	 */
	readonly Version: EngineModule["Version"];

	/**
	 * The message priorities (V2+), valued by their wire ordinals.
	 */
	readonly MessagePriority: EngineModule["MessagePriority"];

	/**
	 * The profile codec: raw bytes in the opaque body wrapper.
	 */
	readonly opaque: MessageCodec<Uint8Array>;

	/**
	 * Frame-in-frame payloads: a codec whose messages are full tightbeam
	 * frames, carried untouched inside the body of another frame.
	 *
	 * The pub/sub registry stamps its wrapper while the published inner frame
	 * relays byte for byte, so the security its publisher applied survives the
	 * broker and verifies on the subscriber.
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
		const ceiling = handle.ceiling(undefined);
		const zstd = ZstdView.over(handle, profile.zstd, ceiling);
		this.#zstd = handle;
		this.#parts = { glue, data: profile.data, sha3_256, zstd };
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
	 * Load the engine of this realm once, through the loader of the build
	 * condition, and resolve with it. A later load resolves the same engine
	 * and ignores its `input`, as the glue does once it started.
	 *
	 * @throws TightbeamTransportError `EngineUnavailable` when the binary is
	 * missing or does not start, with the platform failure as its `cause`.
	 */
	static load(input?: EngineInput): Promise<Engine> {
		const held = Engine.#loading;
		if (held !== undefined) {
			return held;
		}

		// The start is async, so a loader that throws as it is called rejects
		// the start, and the catch clears the memo for every failure.
		const loading = Engine.#start(input);
		Engine.#loading = loading;
		void loading.catch(() => {
			Engine.#loading = undefined;
		});

		return loading;
	}

	/**
	 * Start the glue from `input` and build the engine over it, or reject
	 * with `EngineUnavailable`. {@link load} is the one caller of the loader,
	 * so its memo is the one home of a single start per realm.
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

	/**
	 * The glue of the loaded module.
	 */
	get #glue(): EngineModule {
		return this.#parts.glue;
	}

	/**
	 * Narrow an unknown rejection to a structured {@link TransportError}: an
	 * `Error` with the name brand of a transport error, whose `code` is a code
	 * that the engine or the client declares. A forged error that carries the
	 * brand and an unknown code does not narrow.
	 */
	isTransportError(value: unknown): value is TransportError {
		const code = ClientTransportError[BRANDED_CODE](value);
		if (code === undefined) {
			return false;
		}

		const engineCode = this.#glue.Codes.has(code);
		const declared = engineCode || ClientTransportError[DECIDES](code);
		return declared;
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
		const digests = this.#glue.DigestInfo;
		const of = (oid: Oid): DigestInfo => digests.of(oid, digest);

		const info = Lent.oid(algorithmOid, of);
		return info;
	}

	/**
	 * The profile zstd compression, whose decompression stops at `maxOutput`
	 * octets (16 MiB by default). The realm owns one zstd handle and lends it
	 * as a view, and the view holds the ceiling the engine parsed, so a
	 * ceiling leaves no handle behind.
	 *
	 * @throws TightbeamTransportError `InvalidMaxOutput` when `maxOutput` is
	 * no whole, non-negative number.
	 */
	zstd(maxOutput?: number): ZstdView {
		if (maxOutput === undefined) {
			return this.#parts.zstd;
		}

		const ceiling = this.#zstd.ceiling(maxOutput);
		const zstd = ZstdView.over(this.#zstd, this.profile.zstd, ceiling);
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
	 * Begin building a frame, and seed its body with the raw bytes `message`
	 * under the profile opaque wrapper when one is given.
	 */
	frameBuilder(message?: Uint8Array): FrameBuilder {
		const builder = FrameBuilder.of(this.#parts, message);
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
	 * The opening of a commitment over `bodyDer` under `salt`. The opening
	 * takes the salt, so `salt` keeps an empty shell that frees as any handle
	 * does.
	 *
	 * @throws TightbeamTransportError `CommitmentSpent` when the salt moved
	 * out of `salt` already.
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
		const key = Secp256k1SigningKey.fromBytes(this.#glue, bytes);
		return key;
	}

	/**
	 * Wrap a SEC1-encoded point (33-byte compressed or 65-byte uncompressed).
	 *
	 * @throws TightbeamTransportError `InvalidVerifyingKey` when the octets
	 * name no secp256k1 point.
	 */
	verifyingKey(sec1: Uint8Array): Secp256k1VerifyingKey {
		const key = Secp256k1VerifyingKey.fromSec1Bytes(this.#glue, sec1);
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
		const cipher = Aes256Gcm.fromKey(this.#glue, shared);
		return cipher;
	}

	/**
	 * Wrap the SEC1-encoded public key of a recipient.
	 *
	 * @throws TightbeamTransportError `InvalidVerifyingKey` when the octets
	 * name no secp256k1 point.
	 */
	hpkeEncryptor(recipientPublicKey: Uint8Array): HpkeEncryptor {
		const glue = this.#glue;
		const encryptor = HpkeEncryptor.fromBytes(glue, recipientPublicKey);
		return encryptor;
	}

	/**
	 * Wrap the raw 32-byte secret key of a recipient.
	 *
	 * @throws TightbeamTransportError `InvalidSigningKey` when the secret is
	 * not 32 octets, or names no key.
	 */
	hpkeDecryptor(secretKey: Uint8Array): HpkeDecryptor {
		const decryptor = HpkeDecryptor.fromBytes(this.#glue, secretKey);
		return decryptor;
	}

	/**
	 * Open a server-authenticated multiplexed session to `url`, pinning
	 * `serverCertDer` as the trusted server. Resolves once the handshake
	 * completes and multiplexing is negotiated.
	 *
	 * @throws TightbeamTransportError, as the call throws, `InvalidStreamCap`
	 * when the cap is no whole number from 1 to 2^32-1, and
	 * `SessionOfferRequiresMutual` when the options name a session knob.
	 */
	async connect(
		url: string,
		serverCertDer: Uint8Array,
		options?: ConnectOptions,
	): Promise<TightbeamWsClient> {
		const connector = this.#glue.MuxWsClient;
		const dialing = connector.connect(url, serverCertDer, options);
		const socket = await dialing;

		const client = TightbeamWsClient[OVER](this, socket);
		return client;
	}

	/**
	 * As {@link connect}, and present a client identity for mutual
	 * authentication. The proof of the certificate key is the raw 32-byte
	 * secp256k1 scalar, or an external `TransportSigner` (WebAuthn, wallet,
	 * KMS bridge) whose key stays in its JavaScript backend.
	 *
	 * @throws TightbeamTransportError `InvalidBytes` when a certificate is
	 * not a `Uint8Array`, `InvalidClientKey` when the key is neither the raw
	 * scalar nor signer-shaped, and `InvalidStreamCap` as {@link connect}
	 * does.
	 */
	async connectMutual(
		url: string,
		identity: MutualIdentity,
		options?: MutualConnectOptions,
	): Promise<TightbeamWsClient> {
		const connector = this.#glue.MuxWsClient;
		const dialing = connector.connectMutual(url, identity, options);
		const socket = await dialing;

		const client = TightbeamWsClient[OVER](this, socket);
		return client;
	}

	/**
	 * Open a cleartext multiplexed session to `url`. The promise resolves once
	 * the socket is open, so a failed dial rejects here rather than on the
	 * first emit.
	 *
	 * - Cleartext multiplexing has no handshake negotiation, so the cap is
	 *   symmetric and both endpoints MUST configure the same value.
	 * - The connection carries NO confidentiality or integrity protection.
	 *
	 * @throws TightbeamTransportError as {@link connect} does.
	 */
	async connectCleartext(
		url: string,
		options?: CleartextConnectOptions,
	): Promise<TightbeamWsClient> {
		const dialing = this.#glue.MuxWsClient.connectCleartext(url, options);
		const socket = await dialing;

		const client = TightbeamWsClient[OVER](this, socket);
		return client;
	}
}
