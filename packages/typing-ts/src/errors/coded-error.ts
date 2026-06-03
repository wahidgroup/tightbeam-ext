/**
 * Abstract base for all standardized errors.
 */

import type { FieldDef } from "../shape.js";
import { isShape } from "../shape.js";

/**
 * Abstract base class for errors with a two-level discriminant.
 *
 * - `kind` - category prefix (e.g., `"E_USER"`, `"E_API"`)
 * - `code` - specific identifier freely defined by consumers
 */
export abstract class CodedError extends Error {
	/**
	 * Category prefix for this error class.
	 */
	abstract readonly kind: string;

	/**
	 * Specific error identifier defined by the consumer.
	 */
	abstract readonly code: string;

	constructor(message: string, cause?: unknown) {
		super(message, { cause });
		this.name = this.constructor.name;
	}

	/**
	 * Fully qualified error code combining `kind` and `code`.
	 */
	get qualifiedCode(): string {
		const qualified = `${this.kind}_${this.code}`;
		return qualified;
	}

	/**
	 * Structured JSON representation for serialization.
	 */
	toJSON(): Record<string, unknown> {
		const json: Record<string, unknown> = {
			name: this.name,
			kind: this.kind,
			code: this.code,
			qualifiedCode: this.qualifiedCode,
			message: this.message,
			cause: this.cause,
		};
		return json;
	}

	/**
	 * Duck-type validation helper for subclass `isInstance` guards.
	 */
	static isInstance(
		err: unknown,
		kind: string,
		spec?: Record<string, FieldDef>,
	): boolean {
		const baseSpec: Record<string, FieldDef> = {
			kind: "string",
			code: "string",
			message: "string",
			...spec,
		};

		if (!isShape(err, baseSpec)) {
			return false;
		}

		const errKind: unknown = Reflect.get(err, "kind");
		return errKind === kind;
	}
}
