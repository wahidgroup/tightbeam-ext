/**
 * The error surface of the client, as the transport errors section of `docs/ws-client.md` describes.
 */

import type {
	BodyLayer,
	Codes,
	EngineFault,
	FaultOf,
	OpaqueBodyFault,
	TransitRefusal,
	TransportErrorName,
} from "#wasm";

/**
 * Refuse a server-initiated stream with a chosen status.
 *
 * A `serve` handler throws it, or rejects with it, and the peer receives its
 * `code` in place of the generic `Unknown`.
 */
export class StreamRefusal extends Error {
	override readonly name: string = "StreamRefusal";

	readonly #code: TransitRefusal;

	constructor(code: TransitRefusal, message: string) {
		super(message);
		this.#code = code;
	}

	/**
	 * The status that a served stream answers when its handler throws
	 * `thrown`: the code of a `StreamRefusal`, and `Unknown` for any other
	 * value, such as a rethrown transport error or a bare status name.
	 */
	static settlement(thrown: unknown): TransitRefusal {
		const refusal = typeof thrown === "object" && thrown !== null && #code in thrown;
		if (!refusal) {
			return "Unknown";
		}

		return thrown.#code;
	}

	/**
	 * The gRPC canonical status that the peer receives for this refusal.
	 */
	get code(): TransitRefusal {
		return this.#code;
	}
}

/**
 * Every code of a failure that the TypeScript client decides itself, before a
 * call reaches the engine. {@link ClientCode} reads its members from this one
 * list, and one static of {@link ClientTransportError} builds each code.
 */
const CLIENT_CODES = [
	"KeyReleased",
	"OpeningReleased",
	"CodecReleased",
	"EngineUnavailable",
	"CompactnessRefused",
	"EnvelopeSender",
	"EnvelopeReceiver",
	"EnvelopeCleartext",
	"EnvelopeUnsigned",
] as const;

/**
 * The code of a failure that the TypeScript client decides itself.
 */
export type ClientCode = (typeof CLIENT_CODES)[number];

/**
 * A transport error whose `code` the TypeScript client decides itself.
 */
export type ClientFault = FaultOf<ClientCode>;

/**
 * A structured transport failure, from the wasm layer or from the client. The
 * type has one member per family of its code, so a check of `code` narrows to
 * the member that carries its detail. The transport errors section of
 * `docs/ws-client.md` gives the meaning of each code that callers branch on.
 */
export type TransportError = EngineFault | ClientFault;

/**
 * Every code a {@link TransportError} carries.
 */
export type TransportErrorCode = TransportError["code"];

/**
 * The codes that the client decides before a call crosses the boundary: its
 * own codes, and the engine codes it raises on a released handle or an
 * opaque body.
 */
type ClientDecided = ClientCode | "ConnectionClosed" | "StreamClosed" | "OpaqueBody";

/**
 * The name brand of every structured transport error, which the engine sets
 * on its own errors too.
 */
const TRANSPORT_ERROR_NAME: TransportErrorName = "TightbeamTransportError";

/**
 * The `code` of `error` when it carries the name brand of a transport error,
 * before any check of the code's membership.
 */
function brandedCode(error: unknown): string | undefined {
	if (!(error instanceof Error) || error.name !== TRANSPORT_ERROR_NAME) {
		return undefined;
	}

	const code: unknown = Reflect.get(error, "code" satisfies keyof FaultOf<string>);
	if (typeof code !== "string") {
		return undefined;
	}

	return code;
}

/**
 * A {@link TransportError} that the client decides before a call crosses the
 * boundary. One named static builds each code, and the constructor is
 * private, so only `opaqueBody` pairs a code with a `layer`.
 */
export class ClientTransportError
	extends Error
	implements Pick<FaultOf<ClientDecided>, "name" | "code" | "path">, Partial<Pick<OpaqueBodyFault, "layer">>
{
	override readonly name = TRANSPORT_ERROR_NAME;

	/**
	 * The code that names the failure.
	 */
	readonly code: ClientDecided;

	/**
	 * The field the refusal concerns, when it concerns one.
	 */
	readonly path?: string;

	/**
	 * The layer an `OpaqueBody` refusal lacks a capability for.
	 */
	readonly layer?: BodyLayer;

	private constructor(
		code: ClientDecided,
		message: string,
		options?: ErrorOptions & {
			readonly path?: string;
			readonly layer?: BodyLayer;
		},
	) {
		super(message, options);
		this.code = code;
		if (options?.path !== undefined) {
			this.path = options.path;
		}
		if (options?.layer !== undefined) {
			this.layer = options.layer;
		}
	}

	/**
	 * The rejection for `operation` on a released client: the same
	 * `ConnectionClosed` code that in-flight emits settle with when the
	 * connection drops.
	 */
	static closed(operation: string): ClientTransportError {
		const message = `Cannot ${operation}: the client is closed and its wasm resources are released`;
		const closed = new ClientTransportError("ConnectionClosed", message);
		return closed;
	}

	/**
	 * The rejection for `operation` on a stream whose owner closed or
	 * released its wasm handle: the same `StreamClosed` code that the wasm
	 * layer gives a stream half that a close consumed.
	 */
	static streamClosed(operation: string): ClientTransportError {
		const message = `Cannot ${operation}: the stream is closed and its wasm handle is released`;
		const closed = new ClientTransportError("StreamClosed", message);
		return closed;
	}

	/**
	 * The rejection of a read of a body whose `layer` the read holds no
	 * capability for: the same `OpaqueBody` code that the engine gives a
	 * commitment over a sealed or compressed body.
	 */
	static opaqueBody(layer: BodyLayer): ClientTransportError {
		const message = `The frame body needs an ${layer} before it decodes`;
		const opaque = new ClientTransportError("OpaqueBody", message, {
			layer,
		});
		return opaque;
	}

	/**
	 * The rejection for `operation` on a profile key whose wasm handle its
	 * owner released.
	 */
	static keyReleased(operation: string): ClientTransportError {
		const message = `Cannot ${operation}: the key is released and its wasm handle is freed`;
		const released = new ClientTransportError("KeyReleased", message);
		return released;
	}

	/**
	 * The rejection for `operation` on a commitment opening whose owner
	 * released its salt.
	 */
	static openingReleased(operation: string): ClientTransportError {
		const message = `Cannot ${operation}: the opening is released and its salt is freed`;
		const released = new ClientTransportError("OpeningReleased", message);
		return released;
	}

	/**
	 * The rejection for `operation` on a held codec whose holder disposed it
	 * and freed its copy of the content type.
	 */
	static codecReleased(operation: string): ClientTransportError {
		const message = `Cannot ${operation}: the codec is released and its content type is freed`;
		const released = new ClientTransportError("CodecReleased", message);
		return released;
	}

	/**
	 * The rejection of an engine load that failed with `cause`: the binary is
	 * missing, the platform refused it, or its glue failed to start.
	 */
	static engineUnavailable(cause: unknown): ClientTransportError {
		const message = "The WebAssembly engine did not load";
		const unavailable = new ClientTransportError("EngineUnavailable", message, { cause });
		return unavailable;
	}

	/**
	 * The refusal of an inflator that names another algorithm than the
	 * compactness info names, `algorithm`, or that refuses its parameters.
	 */
	static compactnessRefused(algorithm: string): ClientTransportError {
		const message = `The inflator does not reverse a body compressed with ${algorithm}`;
		const refused = new ClientTransportError("CompactnessRefused", message, {
			path: "compactness",
		});
		return refused;
	}

	/**
	 * The refusal of an envelope that frames a message while a declared layer
	 * holds no send half.
	 */
	static envelopeSender(): ClientTransportError {
		const message = "A declared layer holds no send half: name its signer and sealer to build frames";
		const refused = new ClientTransportError("EnvelopeSender", message);
		return refused;
	}

	/**
	 * The refusal of an envelope that unwraps a frame while a declared layer
	 * holds no receive half.
	 */
	static envelopeReceiver(): ClientTransportError {
		const message = "A declared layer holds no receive half: name its verifier and opener to unwrap frames";
		const refused = new ClientTransportError("EnvelopeReceiver", message);
		return refused;
	}

	/**
	 * The refusal of a signed envelope that unwraps an unsigned frame, which
	 * would downgrade the conversation.
	 */
	static envelopeUnsigned(): ClientTransportError {
		const message = "The envelope declares authenticity but the frame is unsigned: refusing the downgrade";
		const refused = new ClientTransportError("EnvelopeUnsigned", message);
		return refused;
	}

	/**
	 * The refusal of a sealed envelope that unwraps a cleartext frame, which
	 * would downgrade the conversation.
	 */
	static envelopeCleartext(): ClientTransportError {
		const message = "The envelope declares confidentiality but the frame body is cleartext: refusing the downgrade";
		const refused = new ClientTransportError("EnvelopeCleartext", message);
		return refused;
	}
}

/**
 * The recognizer of the transport error family over the code table of one
 * loaded engine, which `Engine.isTransportError` holds.
 */
export class TransportErrors {
	readonly #codes: typeof Codes;

	private constructor(codes: typeof Codes) {
		this.#codes = codes;
	}

	/**
	 * The recognizer over `codes`, the code table of the loaded glue.
	 */
	static over(codes: typeof Codes): TransportErrors {
		const errors = new TransportErrors(codes);
		return errors;
	}

	/**
	 * Whether `value` is a structured {@link TransportError}: an `Error` with
	 * the name brand of a transport error, whose `code` the client declares,
	 * or whose code and detail the engine declares. A forged error that
	 * carries the brand and an unknown code is no transport error.
	 */
	recognizes(value: unknown): value is TransportError {
		const code = brandedCode(value);
		if (code === undefined) {
			return false;
		}

		const decided = CLIENT_CODES.some((member) => member === code);
		const recognized = decided || this.#codes.recognizes(value);
		return recognized;
	}
}
