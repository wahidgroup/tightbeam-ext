/**
 * A fluent, immutable builder for tightbeam frames, assembled by the wasm
 * structure engine.
 */

import type {
	CommitmentSalt,
	FrameAssembly,
	FrameComposer,
	MessagePriority,
	Oid,
	Signing,
	Version,
} from "#wasm";

import type { BodyCompressor } from "../compress.js";
import type { BodyEncryptor, Hasher, Signatory } from "../crypto.js";
import type { EngineParts } from "../engine.js";
import type { MessageCodec } from "../message.js";
import type { DigestName, OidName } from "../views.js";
import type { ValidationIssue } from "./errors.js";
import type { FrameSpec, MessageSlot } from "./spec.js";
import { HeldCompressor } from "../compress.js";
import { HeldHasher } from "../crypto.js";
import { InternalError } from "../errors.js";
import { Frame } from "../frame.js";
import { Codecs, HeldCodec } from "../message.js";
import { DigestInfoView, Lent, OidView } from "../views.js";
import { ValidationError } from "./errors.js";

/**
 * The octets of the plain-digest salt, for a commitment that names none.
 */
const EMPTY_SALT = new Uint8Array();

/**
 * UTF-8 encoder.
 */
const UTF8 = new TextEncoder();

/**
 * Coerces a `Uint8Array | string` into bytes, encoding strings as UTF-8.
 */
function toBytes(value: Uint8Array | string): Uint8Array {
	if (typeof value === "string") {
		const bytes = UTF8.encode(value);
		return bytes;
	}

	return value;
}

/**
 * A codec and the message it encodes, held as a deferred body encoding. The
 * slot erases the codec's type parameter from the spec, and holds the codec
 * under a copy of the content type it declares, so a free of the codec's
 * handle leaves the build its own.
 */
class CodecSlot<T> implements MessageSlot {
	readonly #codec: HeldCodec<T>;

	constructor(
		codec: MessageCodec<T>,
		private readonly message: T,
	) {
		this.#codec = HeldCodec.of(codec);
	}

	get contentOid(): OidView | undefined {
		return this.#codec.contentOid;
	}

	/**
	 * Whether `value` is a codec rather than raw bytes. The check reads the
	 * shape of `value` alone, so bytes of any realm take the raw-bytes path,
	 * and the engine reads them at the build.
	 */
	static isCodec<T>(
		value: Uint8Array | MessageCodec<T>,
	): value is MessageCodec<T> {
		const encode: unknown = Reflect.get(value, "encode");
		const isCodec = typeof encode === "function";
		return isCodec;
	}

	encodeBody(): Uint8Array {
		const body = this.#codec.encode(this.message);
		return body;
	}
}

/**
 * A fluent, immutable frame builder. Each `with*` call returns a new
 * builder, and {@link build} assembles the frame through the wasm engine,
 * which also decides the version floor and parses every value it receives.
 */
export class FrameBuilder {
	private readonly spec: FrameSpec;

	readonly #parts: EngineParts;

	/**
	 * The salt `withCommitment` took, which no public path reaches.
	 */
	readonly #commitment: CommitmentSalt | undefined;

	private constructor(
		parts: EngineParts,
		spec: FrameSpec,
		commitment?: CommitmentSalt,
	) {
		this.#parts = parts;
		this.spec = spec;
		this.#commitment = commitment;
	}

	/**
	 * Begin building a tightbeam frame through the engine `parts` (the same
	 * API as the tightbeam-rs `compose!` surface), and seed the body with the
	 * raw bytes `message` under the profile opaque wrapper when one is given.
	 */
	static of(parts: EngineParts, message?: Uint8Array): FrameBuilder {
		const builder = new FrameBuilder(parts, {});
		if (message === undefined) {
			return builder;
		}

		const seeded = builder.withMessage(message);
		return seeded;
	}

	private with(patch: Partial<FrameSpec>): FrameBuilder {
		const spec = { ...this.spec, ...patch };
		const next = new FrameBuilder(this.#parts, spec, this.#commitment);
		return next;
	}

	/**
	 * Pin the protocol version explicitly. Without a pin the engine uses the
	 * lowest version that admits the requested fields, and a pin below that
	 * floor fails the build with an `UnsupportedField` error.
	 */
	withVersion(version: Version): FrameBuilder {
		const next = this.with({ version });
		return next;
	}

	/**
	 * Assert the version the assembled frame will carry: `build` fails when
	 * the frame the engine built carries another version.
	 */
	assertVersion(version: Version): FrameBuilder {
		const next = this.with({ assertedVersion: version });
		return next;
	}

	/**
	 * Set the opaque message identifier.
	 */
	withId(id: Uint8Array | string): FrameBuilder {
		const next = this.with({ id: toBytes(id) });
		return next;
	}

	/**
	 * Set the frame order stamp: a whole number or a `bigint` from 0 to
	 * 2^64-1, which the engine parses at the build.
	 *
	 * The value is protocol-opaque. Any monotonic scheme works, such as a
	 * Unix timestamp or a dense per-channel counter. When omitted, the
	 * build defaults it to the current Unix time in seconds.
	 */
	withOrder(order: bigint | number): FrameBuilder {
		const next = this.with({ order });
		return next;
	}

	/**
	 * Set the frame body: raw bytes follow the profile opaque wrapper, while
	 * a `MessageCodec<T>` carries a typed message under the implementor's
	 * schema. Encoding is deferred to `build()`.
	 */
	withMessage(message: Uint8Array): FrameBuilder;
	withMessage<T>(codec: MessageCodec<T>, message: T): FrameBuilder;
	withMessage<T>(
		messageOrCodec: Uint8Array | MessageCodec<T>,
		...rest: [T] | []
	): FrameBuilder {
		if (!CodecSlot.isCodec(messageOrCodec)) {
			const opaque = Codecs.over(this.#glue).opaque;
			const slot = new CodecSlot(opaque, messageOrCodec);
			const next = this.with({ message: slot });
			return next;
		}

		if (rest.length === 1) {
			const [message] = rest;
			const slot = new CodecSlot(messageOrCodec, message);

			const next = this.with({ message: slot });
			return next;
		}

		throw new InternalError(
			"MESSAGE_ARITY",
			"withMessage(codec, message) requires the message argument",
		);
	}

	/**
	 * Set the body content-type OID. The builder holds a copy of `oid`, so a
	 * free of the caller's handle leaves the build its own.
	 */
	withContentOid(oid: OidName): FrameBuilder {
		const contentOid = OidView.copyOf(oid);
		const next = this.with({ contentOid });
		return next;
	}

	/**
	 * Set the message priority (V2+).
	 */
	withPriority(priority: MessagePriority): FrameBuilder {
		const next = this.with({ priority });
		return next;
	}

	/**
	 * Set the time-to-live in seconds (V2+): a whole number or a `bigint` from
	 * 0 to 2^64-1, which the engine parses at the build.
	 */
	withLifetime(seconds: bigint | number): FrameBuilder {
		const next = this.with({ lifetime: seconds });
		return next;
	}

	/**
	 * Link this frame to a parent by its content digest (V2+). The builder
	 * holds a copy of `parent`, so a free of the caller's handle leaves the
	 * build its own.
	 */
	withPreviousHash(parent: DigestName): FrameBuilder {
		const copy = parent.clone();
		const previousHash = DigestInfoView.over(copy, copy.algorithmOid);
		const next = this.with({ previousHash });
		return next;
	}

	/**
	 * Set an N×N control matrix from row-major bytes (V3+).
	 */
	withMatrix(n: number, data: Uint8Array): FrameBuilder {
		const next = this.with({ matrix: { n, data } });
		return next;
	}

	/**
	 * Commit to the message body under any `Hasher` (V1+). The profile
	 * hasher is `Engine.sha3_256`. Bring your own hasher for other digests.
	 *
	 * Without {@link withCommitment} the commitment is a plain digest of the
	 * body. The builder holds a copy of the algorithm the hasher names, so a
	 * free of the caller's handle leaves the build its own.
	 */
	withMessageHasher(hasher: Hasher): FrameBuilder {
		const messageIntegrity = new HeldHasher(hasher);
		const next = this.with({ messageIntegrity });
		return next;
	}

	/**
	 * Hide the message commitment behind `salt`, which the builder takes.
	 *
	 * - The caller keeps an empty shell that frees as any handle does, so a
	 *   disposal of `salt` after this call leaves the builder its salt.
	 * - A salt commits one frame, so the builder, and every builder made from
	 *   it, builds once. A second build refuses with `CommitmentSpent`.
	 *
	 * @throws TightbeamTransportError `CommitmentSpent` when the salt moved out
	 * of `salt` already.
	 */
	withCommitment(salt: CommitmentSalt): FrameBuilder {
		const taken = salt.take();
		const next = new FrameBuilder(this.#parts, this.spec, taken);
		return next;
	}

	/**
	 * Witness the envelope with frame integrity under any `Hasher` (V1+). The
	 * builder holds a copy of the algorithm the hasher names, as
	 * {@link withMessageHasher} does.
	 */
	withWitnessHasher(hasher: Hasher): FrameBuilder {
		const frameIntegrity = new HeldHasher(hasher);
		const next = this.with({ frameIntegrity });
		return next;
	}

	/**
	 * Compress the message body with any `BodyCompressor` (any version).
	 * Compression runs after the message commitment (the commitment is over
	 * the uncompressed body) and before encryption (peers encrypt the
	 * compressed bytes). Inflate the received body with
	 * `Frame.open(codec, { inflator })`.
	 *
	 * The builder holds a copy of the `algorithmOid` the compressor names, so
	 * every build of it records that algorithm, and the compressor keeps its
	 * own handle.
	 */
	withCompressor(compressor: BodyCompressor): FrameBuilder {
		const held = new HeldCompressor(compressor);
		const next = this.with({ compressor: held });
		return next;
	}

	/**
	 * Encrypt the message body with any `BodyEncryptor` (V1+).
	 *
	 * The profile encryptors are `Aes256Gcm` (shared key) and
	 * `HpkeEncryptor` (to a recipient public key). Bring your own
	 * encryptor for other schemes. Open the received body with
	 * `Frame.open(codec, { opener })`.
	 */
	withEncryptor(encryptor: BodyEncryptor): FrameBuilder {
		const next = this.with({ encryptor });
		return next;
	}

	/**
	 * Sign the assembled frame with any `Signatory` (V1+) - the profile
	 * `Secp256k1SigningKey`, or an external implementation (wallet, passkey,
	 * HSM) whose private key never enters wasm memory.
	 */
	withSigner(signatory: Signatory): FrameBuilder {
		const next = this.with({ signer: signatory });
		return next;
	}

	/**
	 * Return a frozen copy of the accumulated specification without
	 * assembling a frame.
	 */
	toSpec(): Readonly<FrameSpec> {
		const spec = Object.freeze({ ...this.spec });
		return spec;
	}

	/**
	 * Validate the accumulated spec and assemble the frame through the wasm
	 * engine, driving the configured hashers, compressor, encryptor, and
	 * signatory in protocol order.
	 *
	 * @throws ValidationError when the spec is structurally invalid or the
	 * built frame carries another version than {@link assertVersion} named.
	 * @throws TightbeamTransportError `UnsupportedField` when a pinned version
	 * is below the floor of a requested field, and the engine's refusal of a
	 * field with the field on `path`, such as `InvalidMatrixDimension` at
	 * `matrix.n`.
	 */
	async build(): Promise<Frame> {
		const issues = this.issues();
		if (issues.length > 0) {
			throw new ValidationError("FRAME_SPEC", issues);
		}

		const der = await this.compose();
		const frame = Frame.decode(this.#parts, der);
		const built = this.assertBuilt(frame);
		return built;
	}

	/**
	 * Collect every structural issue in the accumulated spec (empty when
	 * valid).
	 */
	private issues(): ValidationIssue[] {
		const { message, messageIntegrity } = this.spec;
		const commitment = this.#commitment;
		const issues: ValidationIssue[] = [];

		if (message === undefined) {
			issues.push({
				path: "message",
				message: "Missing required field: message",
			});
		}
		if (commitment !== undefined && messageIntegrity === undefined) {
			issues.push({
				path: "commitment",
				message: "A commitment salt needs withMessageHasher",
			});
		}

		return issues;
	}

	/**
	 * Verify the version the engine wrote matches the caller's assertion.
	 */
	private assertBuilt(frame: Frame): Frame {
		const asserted = this.spec.assertedVersion;
		if (asserted !== undefined && frame.version !== asserted) {
			throw new ValidationError("FRAME_SPEC", [
				{
					path: "assertedVersion",
					message: `Version assertion failed: asserted V${asserted}, but the engine built V${frame.version}`,
				},
			]);
		}

		return frame;
	}

	/**
	 * Assemble the frame DER: the structural frame first, then each security
	 * artifact over the frame before it. The engine holds the frame between
	 * the steps and refuses a step out of protocol order. The slot frees the
	 * handle it holds on every exit of the build.
	 */
	private async compose(): Promise<Uint8Array> {
		const bodyDer = this.bodyDer();
		const slot = new AssemblySlot(new this.#glue.FrameComposer());
		try {
			this.structural(slot.composer, bodyDer);
			slot.assemble();
			await this.secure(slot, bodyDer);

			const der = slot.live.encode();
			return der;
		} finally {
			slot[Symbol.dispose]();
		}
	}

	/**
	 * Install each security artifact of the spec on the frame in `slot`, in
	 * protocol order.
	 */
	private async secure(
		slot: AssemblySlot,
		bodyDer: Uint8Array,
	): Promise<void> {
		const spec = this.spec;
		if (spec.messageIntegrity !== undefined) {
			const hasher = spec.messageIntegrity;
			const preimage = this.commitmentPreimage(slot.live);
			const digest = await hasher.digest(preimage);

			const commit = (algorithmOid: Oid): void => {
				const step = (live: FrameAssembly): FrameAssembly =>
					live.withMessageIntegrity(algorithmOid, digest);
				slot.advance(step);
			};
			Lent.oid(hasher.algorithmOid, commit);
		}

		// The bytes the encryptor seals: the compressed body when a
		// compressor is configured (peers decompress after decrypting).
		let sealInput = bodyDer;
		if (spec.compressor !== undefined) {
			const compressor = spec.compressor;
			const compressed = await compressor.compress(bodyDer);
			const { data, parametersDer } = compressed;
			const compact = (algorithmOid: Oid): void => {
				const step = (live: FrameAssembly): FrameAssembly =>
					live.withCompactness(algorithmOid, data, parametersDer);
				slot.advance(step);
			};

			Lent.oid(compressor.algorithmOid, compact);
			sealInput = data;
		}

		if (spec.encryptor !== undefined) {
			const contentOid = this.contentOid();
			const sealed = await spec.encryptor.encrypt(sealInput, contentOid);
			slot.advance((live) => live.withConfidentiality(sealed));
		}
		if (spec.frameIntegrity !== undefined) {
			const hasher = spec.frameIntegrity;
			const preimage = slot.live.witnessPreimage();
			const digest = await hasher.digest(preimage);

			const witness = (algorithmOid: Oid): void => {
				slot.advance((live) => live.withWitness(algorithmOid, digest));
			};
			Lent.oid(hasher.algorithmOid, witness);
		}
		if (spec.signer !== undefined) {
			await slot.sign(spec.signer);
		}
	}

	/**
	 * The message-commitment preimage over the body that `assembly` holds,
	 * under the salt of the spec, or the plain-digest salt without one.
	 *
	 * Each build takes the salt into a build-local handle and frees it, so the
	 * builder keeps an empty shell and a second build refuses with
	 * `CommitmentSpent`.
	 */
	private commitmentPreimage(assembly: FrameAssembly): Uint8Array {
		const salt = this.buildSalt();
		try {
			const preimage = assembly.commitmentPreimage(salt);
			return preimage;
		} finally {
			salt.free();
		}
	}

	/**
	 * The build-local salt of the commitment: the salt the spec names, taken
	 * out of its shell, or the plain-digest salt without one.
	 */
	private buildSalt(): CommitmentSalt {
		const commitment = this.#commitment;
		if (commitment === undefined) {
			const plain = this.#glue.CommitmentSalt.parse(EMPTY_SALT);
			return plain;
		}

		const taken = commitment.take();
		return taken;
	}

	/**
	 * The content type the encryptor seals the body as: the one the builder
	 * names, the one the codec declares, or the `id-data` the engine holds.
	 */
	private contentOid(): OidName {
		const named = this.spec.contentOid ?? this.spec.message?.contentOid;
		if (named !== undefined) {
			return named;
		}

		return this.#parts.data;
	}

	/**
	 * The glue of the loaded module.
	 */
	get #glue(): EngineParts["glue"] {
		return this.#parts.glue;
	}

	/**
	 * The body DER installed in the frame, committed to by the hashers, and
	 * sealed by the encryptor: the deferred message encoding, or the empty
	 * profile body for a message-less spec.
	 */
	private bodyDer(): Uint8Array {
		const message = this.spec.message;
		if (message === undefined) {
			const empty = new Uint8Array();
			const bodyDer = this.#glue.OpaqueCodec.encode(empty);
			return bodyDer;
		}

		const bodyDer = message.encodeBody();
		return bodyDer;
	}

	/**
	 * Set the structural frame on `composer`: the metadata, and a declaration
	 * of each security field installed afterwards, so the engine sets the
	 * version floor over every field the frame carries.
	 */
	private structural(composer: FrameComposer, bodyDer: Uint8Array): void {
		const spec = this.spec;
		composer.withMessage(bodyDer);

		if (spec.version !== undefined) {
			composer.withVersion(spec.version);
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
			Lent.digest(spec.previousHash, (parent) => {
				composer.withPreviousHash(parent);
			});
		}
		this.installMatrix(composer);
		if (spec.messageIntegrity !== undefined) {
			composer.declareMessageIntegrity();
		}
		if (spec.encryptor !== undefined) {
			composer.declareConfidentiality();
		}
		if (spec.frameIntegrity !== undefined) {
			composer.declareFrameIntegrity();
		}
		if (spec.signer !== undefined) {
			composer.declareNonrepudiation();
		}
	}

	/**
	 * Set the control matrix, when one is set, on `composer`. The engine owns
	 * the matrix rule, and its refusal names the field on `path`.
	 */
	private installMatrix(composer: FrameComposer): void {
		const { matrix } = this.spec;
		if (matrix === undefined) {
			return;
		}

		composer.withMatrix(matrix.n, matrix.data);
	}
}

/**
 * The one wasm handle a build holds between its steps.
 *
 * - `composing`: the composer, until it assembles the structural frame.
 * - `assembled`: the live assembly between the security steps.
 * - `signing`: the signature draft while a signatory signs its prehash.
 * - `spent`: no handle, while a step runs or once the slot freed it.
 */
type BuildHandle =
	| { readonly step: "composing"; readonly composer: FrameComposer }
	| { readonly step: "assembled"; readonly assembly: FrameAssembly }
	| { readonly step: "signing"; readonly signing: Signing }
	| { readonly step: "spent" };

/**
 * The slot of a build while a step runs.
 */
const SPENT: BuildHandle = { step: "spent" };

/**
 * The live wasm handle of one build: the composer, until it assembles the
 * structural frame, then the one live assembly, and the signature draft while
 * a signatory signs. Each step consumes the handle it takes, so the slot holds
 * none while a step runs, and holds the result of the step after it. A step
 * that throws drops its handle in wasm, and the slot frees the handle it holds
 * as the build leaves, whether the build ends or throws.
 */
class AssemblySlot implements Disposable {
	private held: BuildHandle;

	constructor(composer: FrameComposer) {
		this.held = { step: "composing", composer };
	}

	/**
	 * The composer, before the structural frame assembles.
	 *
	 * @throws InternalError `COMPOSER_SPENT` once the frame assembled.
	 */
	get composer(): FrameComposer {
		const held = this.held;
		if (held.step !== "composing") {
			throw new InternalError(
				"COMPOSER_SPENT",
				"a build step set the composer after it assembled the frame",
			);
		}

		return held.composer;
	}

	/**
	 * Assemble the structural frame: the build consumes the composer, and the
	 * slot holds the assembly.
	 */
	assemble(): void {
		const composer = this.composer;
		this.held = SPENT;

		const assembly = composer.build();
		this.held = { step: "assembled", assembly };
	}

	/**
	 * The live assembly, for a read that leaves it live.
	 *
	 * @throws InternalError `ASSEMBLY_SPENT` after a step that threw.
	 */
	get live(): FrameAssembly {
		const held = this.held;
		if (held.step !== "assembled") {
			throw new InternalError(
				"ASSEMBLY_SPENT",
				"a build step ran after an earlier step consumed the assembly",
			);
		}

		return held.assembly;
	}

	/**
	 * Replace the live assembly with the result of `step`, which consumes
	 * it.
	 */
	advance(step: (live: FrameAssembly) => FrameAssembly): void {
		const assembly = this.live;
		this.held = SPENT;

		const next = step(assembly);
		this.held = { step: "assembled", assembly: next };
	}

	/**
	 * Replace the live assembly with the frame `signatory` signs. The engine
	 * drafts the signature over the assembly it consumes, the slot holds the
	 * draft while the signatory signs its prehash, and the completed draft
	 * returns the signed frame.
	 */
	async sign(signatory: Signatory): Promise<void> {
		const signerId = signatory.signerId();
		const assembly = this.live;
		this.held = SPENT;

		const signing = assembly.signing(signerId);
		this.held = { step: "signing", signing };
		const signature = await signatory.signPrehash(signing.prehash);

		this.held = SPENT;
		const signed = signing.complete(signature);
		this.held = { step: "assembled", assembly: signed };
	}

	/**
	 * Free the composer, the live assembly, or the signature draft, whichever
	 * the slot holds.
	 */
	[Symbol.dispose](): void {
		const held = this.held;
		this.held = SPENT;

		switch (held.step) {
			case "composing":
				held.composer.free();
				return;
			case "assembled":
				held.assembly.free();
				return;
			case "signing":
				held.signing.free();
				return;
			case "spent":
				return;
			default: {
				const leftover: never = held;
				return leftover;
			}
		}
	}
}
