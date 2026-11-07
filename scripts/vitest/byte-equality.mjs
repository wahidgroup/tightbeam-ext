/**
 * The byte equality that every vitest suite of the repo registers as a setup
 * file. The default matcher compares a `Uint8Array` through its iterator and
 * its entries, one element at a time, at over a second per mebibyte. A suite
 * that echoes a body past the stream credit would then spend its timeout in
 * the matcher rather than on the wire, so this tester compares the octets in
 * one loop.
 *
 * The tester decides a pair of byte arrays of one class by their octets
 * alone. It leaves every other pair to the default rules, such as a `Buffer`
 * against a `Uint8Array` or an asymmetric matcher.
 *
 * # Sources
 *
 * - Vitest, Extending Matchers, Custom Equality Testers
 *   (`expect.addEqualityTesters`).
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
