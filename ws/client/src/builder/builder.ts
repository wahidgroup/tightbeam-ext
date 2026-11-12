/**
 * A fluent, immutable builder for tightbeam frames, assembled by the wasm
 * structure engine.
 */

import type { CommitmentSalt, FrameComposer, MessagePriority, Version } from "#wasm";

import type { BodyCompressor } from "../compress.js";
import type { BodyEncryptor, Hasher, Signatory } from "../crypto.js";
import type { EngineParts } from "../engine.js";
import type { MessageCodec } from "../message.js";
import type { DigestName, OidName } from "../views.js";
import { Frame } from "../frame.js";
import { Codecs, HeldCodec } from "../message.js";
import { DigestInfoView, OidView } from "../views.js";
import { Assembled } from "./assembly.js";
import { SecurityLayers } from "./layers.js";

/**
 * The encoder of a string message identifier, as UTF-8.
 */
const UTF8 = new TextEncoder();

/**
 * The frame body: a codec and the message it encodes, held as a deferred
 * body encoding under a copy of the content type the codec declares.
 */
class MessageBody {
	readonly #encode: () => Uint8Array;

	/**
	 * The content type the codec declares, which the seal records unless the
	 * builder names another.
	 */
	readonly contentOid: OidView | undefined;

	private constructor(encode: () => Uint8Array, contentOid: OidView | undefined) {
		this.#encode = encode;
		this.contentOid = contentOid;
	}

	/**
	 * The body that `codec` encodes from `message`.
	 */
	static of<T>(codec: MessageCodec<T>, message: T): MessageBody {
		const held = HeldCodec.of(codec);
		const encode = (): Uint8Array => held.encode(message);

		const body = new MessageBody(encode, held.contentOid);
		return body;
	}

	/**
	 * The body DER the frame carries.
	 */
	encode(): Uint8Array {
		const bodyDer = this.#encode();
		return bodyDer;
	}
}

/**
 * Everything a build reads, accumulated by the `with*` calls of the builder.
 */
interface BuildSpec {
	readonly body: MessageBody;
	readonly layers: SecurityLayers;
	readonly version?: Version;
	readonly assertedVersion?: Version;
	readonly id?: Uint8Array;
	readonly order?: bigint | number;
	readonly contentOid?: OidView;
	readonly priority?: MessagePriority;
	readonly lifetime?: bigint | number;
	readonly previousHash?: DigestInfoView;
	readonly matrix?: { readonly n: number; readonly data: Uint8Array };
}

/**
 * The key of the record of whether a builder holds a message identifier. A
 * symbol key keeps the record in the emitted declarations, where a private
 * member loses its type.
 */
declare const NAMED: unique symbol;

/**
 * A fluent, immutable frame builder. Each `with*` call returns a new builder,
 * and {@link build} assembles the frame through the wasm engine. `Named`
 * records whether the builder holds the message identifier that every frame
 * carries, so {@link build} exists only on a builder that {@link withId} named.
 */
export class FrameBuilder<Named extends boolean = false> {
	/**
	 * Whether the builder holds a message identifier, recorded in the type
	 * alone.
	 */
	declare readonly [NAMED]: Named;

	readonly #parts: EngineParts;

	readonly #spec: BuildSpec;

	private constructor(parts: EngineParts, spec: BuildSpec) {
		this.#parts = parts;
		this.#spec = spec;
	}

	/**
	 * Begin a frame through the engine `parts` whose body carries the raw
	 * bytes `bytes` under the profile opaque wrapper.
	 *
	 * @internal
	 */
	static bytes(parts: EngineParts, bytes: Uint8Array): FrameBuilder {
		const opaque = Codecs.over(parts.glue).opaque;
		const builder = FrameBuilder.message(parts, opaque, bytes);
		return builder;
	}

	/**
	 * Begin a frame through the engine `parts` whose body carries `message`
	 * under the schema of `codec`. Encoding is deferred to {@link build}.
	 *
	 * @internal
	 */
	static message<T>(parts: EngineParts, codec: MessageCodec<T>, message: T): FrameBuilder {
		const body = MessageBody.of(codec, message);
		const layers = SecurityLayers.none();

		const builder = new FrameBuilder(parts, { body, layers });
		return builder;
	}

	#with<N extends boolean>(patch: Partial<BuildSpec>): FrameBuilder<N> {
		const spec = { ...this.#spec, ...patch };
		const next = new FrameBuilder<N>(this.#parts, spec);
		return next;
	}

	/**
	 * Pin the protocol version explicitly. Without a pin the engine uses the
	 * lowest version that admits the requested fields, and a pin below that
	 * floor fails the build with an `UnsupportedField` error.
	 */
	withVersion(version: Version): FrameBuilder<Named> {
		const next = this.#with<Named>({ version });
		return next;
	}

	/**
	 * Assert the version the assembled frame will carry: the engine refuses
	 * another version with `VersionMismatch` as the structure assembles,
	 * before any hasher, encryptor, or signatory acts.
	 */
	assertVersion(version: Version): FrameBuilder<Named> {
		const next = this.#with<Named>({ assertedVersion: version });
		return next;
	}

	/**
	 * Set the opaque message identifier, which every frame carries. The
	 * builder holds a copy of `id`, so a later write to it leaves the build as
	 * it was.
	 */
	withId(id: Uint8Array | string): FrameBuilder<true> {
		let bytes: Uint8Array;
		if (typeof id === "string") {
			bytes = UTF8.encode(id);
		} else {
			bytes = new Uint8Array(id);
		}

		const next = this.#with<true>({ id: bytes });
		return next;
	}

	/**
	 * Set the frame order stamp: a whole number or a `bigint` from 0 to
	 * 2^64-1, which the engine parses at the build. Any monotonic scheme works,
	 * such as a Unix timestamp or a per-channel counter. A build without one
	 * stamps the current Unix time in seconds.
	 */
	withOrder(order: bigint | number): FrameBuilder<Named> {
		const next = this.#with<Named>({ order });
		return next;
	}

	/**
	 * Set the body content-type OID. The builder holds a copy of `oid`, so a
	 * free of the caller's handle leaves the build its own.
	 */
	withContentOid(oid: OidName): FrameBuilder<Named> {
		const contentOid = OidView.copyOf(oid);
		const next = this.#with<Named>({ contentOid });
		return next;
	}

	/**
	 * Set the message priority (V2+).
	 */
	withPriority(priority: MessagePriority): FrameBuilder<Named> {
		const next = this.#with<Named>({ priority });
		return next;
	}

	/**
	 * Set the time-to-live in seconds (V2+): a whole number or a `bigint` from
	 * 0 to 2^64-1, which the engine parses at the build.
	 */
	withLifetime(seconds: bigint | number): FrameBuilder<Named> {
		const next = this.#with<Named>({ lifetime: seconds });
		return next;
	}

	/**
	 * Link this frame to a parent by its content digest (V2+). The builder
	 * holds a copy of `parent`, so a free of the caller's handle leaves the
	 * build its own.
	 */
	withPreviousHash(parent: DigestName): FrameBuilder<Named> {
		const copy = parent.clone();
		const previousHash = DigestInfoView.over(copy);
		const next = this.#with<Named>({ previousHash });
		return next;
	}

	/**
	 * Set an N×N control matrix from row-major bytes (V3+). The builder holds
	 * a copy of `data`, so a later write to it leaves the build as it was.
	 */
	withMatrix(n: number, data: Uint8Array): FrameBuilder<Named> {
		const matrix = { n, data: new Uint8Array(data) };
		const next = this.#with<Named>({ matrix });
		return next;
	}

	/**
	 * Commit to the body under any `Hasher` (V1+), hidden by `salt` when given. The builder copies the algorithm of
	 * `hasher` and then takes `salt`, and the caller keeps an empty shell.
	 *
	 * @throws TightbeamTransportError `CommitmentSpent` when the salt moved out of `salt` already.
	 * @throws the refusal of `hasher.algorithmOid.clone()`, such as for a freed `Oid`, and `salt` keeps its salt.
	 */
	withMessageHasher(hasher: Hasher, salt?: CommitmentSalt): FrameBuilder<Named> {
		const layers = this.#spec.layers.withCommitment(hasher, salt);
		const next = this.#with<Named>({ layers });
		return next;
	}

	/**
	 * Witness the envelope with frame integrity under any `Hasher` (V1+). The
	 * builder holds a copy of the algorithm the hasher names, so a free of
	 * the caller's handle leaves the build its own.
	 */
	withWitnessHasher(hasher: Hasher): FrameBuilder<Named> {
		const layers = this.#spec.layers.withWitness(hasher);
		const next = this.#with<Named>({ layers });
		return next;
	}

	/**
	 * Compress the message body with any `BodyCompressor` (any version), after
	 * the message commitment and before the encryption. The builder holds a
	 * copy of the `algorithmOid` the compressor names, so every build records
	 * that algorithm.
	 */
	withCompressor(compressor: BodyCompressor): FrameBuilder<Named> {
		const layers = this.#spec.layers.withCompression(compressor);
		const next = this.#with<Named>({ layers });
		return next;
	}

	/**
	 * Encrypt the message body with any `BodyEncryptor` (V1+), such as the
	 * profile `Aes256Gcm` for a shared key or `HpkeEncryptor` for a recipient
	 * public key. Open the received body with `Frame.open(codec, { opener })`.
	 */
	withEncryptor(encryptor: BodyEncryptor): FrameBuilder<Named> {
		const layers = this.#spec.layers.withEncryption(encryptor);
		const next = this.#with<Named>({ layers });
		return next;
	}

	/**
	 * Sign the assembled frame with any `Signatory` (V1+), such as the profile
	 * `Secp256k1SigningKey`, or an external implementation (wallet, passkey,
	 * HSM) whose private key stays in its own backend.
	 */
	withSigner(signatory: Signatory): FrameBuilder<Named> {
		const layers = this.#spec.layers.withSignature(signatory);
		const next = this.#with<Named>({ layers });
		return next;
	}

	/**
	 * Assemble the frame through the wasm engine, then drive the configured
	 * hashers, compressor, encryptor, and signatory in protocol order.
	 *
	 * @throws TightbeamTransportError a refusal that the build rules of
	 * `docs/ws-client.md` name, such as `VersionMismatch` or `CommitmentSpent`.
	 */
	async build(this: FrameBuilder<true>): Promise<Frame> {
		const bodyDer = this.#spec.body.encode();
		const inputs = { parts: this.#parts, contentOid: this.#contentOid() };

		const der = await this.#spec.layers.encode(() => this.#compose(bodyDer), inputs);
		const frame = Frame.decode(this.#parts, der);
		return frame;
	}

	/**
	 * The structural frame over `bodyDer`: the metadata, and a declaration of
	 * each security layer, so the engine sets the version floor over every
	 * field the frame carries. A refused field frees the composer.
	 */
	#compose(bodyDer: Uint8Array): Assembled {
		const composer = new this.#parts.glue.FrameComposer();
		try {
			this.#declare(composer, bodyDer);
		} catch (refusal) {
			composer.free();
			throw refusal;
		}

		const assembled = Assembled.of(composer);
		return assembled;
	}

	/**
	 * Set the structural fields of the spec, and declare each layer, on
	 * `composer`.
	 */
	#declare(composer: FrameComposer, bodyDer: Uint8Array): void {
		const spec = this.#spec;
		composer.withMessage(bodyDer);

		if (spec.version !== undefined) {
			composer.withVersion(spec.version);
		}
		if (spec.assertedVersion !== undefined) {
			composer.assertVersion(spec.assertedVersion);
		}
		if (spec.id !== undefined) {
			composer.withId(spec.id);
		}
		if (spec.order !== undefined) {
			composer.withOrder(spec.order);
		}
		if (spec.priority !== undefined) {
			composer.withPriority(spec.priority);
		}
		if (spec.lifetime !== undefined) {
			composer.withLifetime(spec.lifetime);
		}
		if (spec.previousHash !== undefined) {
			using parent = spec.previousHash.clone();
			composer.withPreviousHash(parent);
		}
		if (spec.matrix !== undefined) {
			composer.withMatrix(spec.matrix.n, spec.matrix.data);
		}

		spec.layers.declare(composer);
	}

	/**
	 * The content type the encryptor seals the body as: the one the builder
	 * names, the one the codec declares, or the `id-data` the engine holds.
	 */
	#contentOid(): OidName {
		const spec = this.#spec;
		const named = spec.contentOid ?? spec.body.contentOid;
		if (named !== undefined) {
			return named;
		}

		return this.#parts.data;
	}
}
