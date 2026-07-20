export type { FrameCodec } from "./codec.js";
export type {
	FrameSpec,
	MatrixSpec,
	MessageIntegritySpec,
	PreviousHashSpec,
} from "./spec.js";
export type { ValidationIssue } from "./errors.js";
export { ValidationError } from "./errors.js";
export { FrameBuilder, effectiveVersion, frame } from "./builder.js";
export { Version, versionFromOrdinal } from "./version.js";
export { MessagePriority, priorityFromOrdinal } from "./priority.js";
