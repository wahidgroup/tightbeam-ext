/**
 * The test rule that every TypeScript package of the repo extends: a suite
 * runs the real engine and the real peers of the stack, so no test swaps in
 * a framework double of owned code, and no test asserts that a call ran.
 * A test asserts what a real run shows instead: a return value, a coded
 * refusal, or what a real peer received.
 *
 * # Sources
 *
 * - `skills/engineer/references/testing.md`, Prefer Real Dependencies, Test
 *   Doubles, and Behavior, Not Implementation.
 */

/**
 * The `vi` members that substitute a module, a function, or a global.
 */
const DOUBLES = [
  "mock",
  "doMock",
  "hoisted",
  "spyOn",
  "fn",
  "stubGlobal",
  "stubEnv",
];

/**
 * The matchers that assert a call ran, or how often.
 */
const CALL_ASSERTIONS = [
  "toHaveBeenCalled",
  "toHaveBeenCalledOnce",
  "toHaveBeenCalledTimes",
  "toHaveBeenCalledWith",
  "toHaveBeenLastCalledWith",
  "toHaveBeenNthCalledWith",
  "toBeCalled",
  "toBeCalledTimes",
  "toBeCalledWith",
];

const DOUBLE_MESSAGE =
  "Run the real engine or the real peer: a framework double replaces the code under test.";

const CALL_MESSAGE =
  "Assert what the run shows, such as a value, a code, or what a peer received, not that a call ran.";

/**
 * The config entry that refuses every double and every call assertion.
 */
export const realDependencies = {
  rules: {
    "no-restricted-properties": [
      "error",
      ...DOUBLES.map((property) => ({
        object: "vi",
        property,
        message: DOUBLE_MESSAGE,
      })),
      ...CALL_ASSERTIONS.map((property) => ({
        property,
        message: CALL_MESSAGE,
      })),
    ],
  },
};
