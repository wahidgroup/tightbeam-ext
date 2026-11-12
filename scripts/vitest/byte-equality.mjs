/**
 * The byte equality that every vitest suite registers as a setup file: docs/development.md (Tests).
 *
 * # Sources
 *
 * - Vitest, Extending Matchers, Custom Equality Testers (`expect.addEqualityTesters`).
 */
import { expect } from "vitest";

/**
 * Whether `actual` and `expected` hold the same octets, or `undefined` when
 * the pair is not two byte arrays of one class.
 */
function byteEquality(actual, expected) {
	const bytes = actual instanceof Uint8Array && expected instanceof Uint8Array;
	const sameClass = bytes && actual.constructor === expected.constructor;
	if (!sameClass) {
		return undefined;
	}
	if (actual.length !== expected.length) {
		return false;
	}

	for (let index = 0; index < actual.length; index += 1) {
		if (actual[index] !== expected[index]) {
			return false;
		}
	}

	return true;
}

expect.addEqualityTesters([byteEquality]);
