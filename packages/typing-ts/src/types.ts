/**
 * Standalone type definitions.
 */

/**
 * Recursive JSON-safe value type.
 */
export type JsonValue =
	| string
	| number
	| boolean
	| null
	| { [key: string]: JsonValue }
	| JsonValue[];
