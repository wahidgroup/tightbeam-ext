/**
 * Client for the tightbeam WebSocket transport (browser and Node).
 *
 * `TightbeamWsClient.init` loads the engine and resolves with the
 * {@link Engine}, the owner of every wasm-backed parse and constructor.
 */

export type {
	CommitmentSalt,
	DigestInfo,
	DigestVerdict,
	GoAwayReason,
	MessagePriority,
	MutualIdentity,
	Oid,
	RefusalCode,
	ServeClaim,
	SharedKey,
	SocketCloseInfo,
	TransitCode,
	TransportCode,
	TransportErrorName,
	TransportSigner,
	Version,
} from "#wasm";
export {
	ClientTransportError,
	InternalError,
	StreamRefusal,
} from "./errors.js";
export type {
	ClientCode,
	InternalCode,
	RefusalStatus,
	TransportError,
	TransportErrorCode,
} from "./errors.js";
export { Engine } from "./engine.js";
export type { EngineInput } from "./engine.js";
export { Frame } from "./frame.js";
export type {
	CompactnessInfo,
	ConfidentialityInfo,
	FrameMatrix,
	IntegrityVerdict,
	OpenOptions,
	PreviousFrame,
	SignatureInfo,
} from "./frame.js";
export { Opening } from "./commitment.js";
export type { ZstdView } from "./compress.js";
export type {
	BodyCompressor,
	BodyInflator,
	CompressedBody,
} from "./compress.js";
export type { DigestInfoView, OidView, ProfileView } from "./views.js";
export type { DigestName, OidName } from "./views.js";
export {
	Aes256Gcm,
	HpkeDecryptor,
	HpkeEncryptor,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	Sha3_256,
} from "./crypto.js";
export type {
	BodyDecryptor,
	BodyEncryptor,
	EncryptedBody,
	FrameVerifier,
	Hasher,
	Signatory,
	VerifiableFrame,
	VerifyingKeyView,
} from "./crypto.js";
export { Envelope } from "./envelope.js";
export { HeldCodec } from "./message.js";
export type { MessageCodec, PayloadCodec } from "./message.js";
export { Route, Router, UnroutedTopicError } from "./router.js";
export type { RouteHandler } from "./router.js";
export { FrameBuilder, ValidationError } from "./builder/index.js";
export type {
	FrameSpec,
	MatrixSpec,
	MessageSlot,
	ValidationCode,
	ValidationIssue,
} from "./builder/index.js";
export { TightbeamWsClient } from "./client.js";
export type {
	CleartextConnectOptions,
	ConnectOptions,
	DuplexBodyHandler,
	DuplexStream,
	EmitOptions,
	MutualConnectOptions,
	MuxStreamHandler,
	ReplySink,
	RequestStream,
	ServeOptions,
	StreamBody,
	StreamRoute,
	StreamingBodyHandler,
	WaitOptions,
} from "./client.js";
