import { describe, expect, it } from "vitest";

import { Command, Topic, TopicError } from "./topic.js";
import WIRE from "./wire.generated.json" with { type: "json" };

/**
 * The longest name the generated limit admits.
 */
const LONGEST = "a".repeat(WIRE.topicMaxLen);

/**
 * The longest name the generated limit admits, in two-octet characters.
 */
const LONGEST_WIDE = "é".repeat(WIRE.topicMaxLen / 2);

const VALID_NAMES = [
	{ label: "a plain name", topic: "prices" },
	{ label: "a hierarchical name", topic: "prices/spot/BTC" },
	{ label: "a reserved word after the start", topic: "orders/sub/updates" },
	{ label: "a name at the generated limit", topic: LONGEST },
	{
		label: "two-octet characters at the generated limit",
		topic: LONGEST_WIDE,
	},
] as const;

const INVALID_NAMES = [
	{ label: "an empty name", topic: "", code: "Empty" },
	{
		label: "one two-octet character past the generated limit",
		topic: `${LONGEST_WIDE}é`,
		code: "TooLong",
	},
	{
		label: "the sub/ command prefix",
		topic: "sub/prices",
		code: "ReservedPrefix",
	},
	{
		label: "the unsub/ command prefix",
		topic: "unsub/prices",
		code: "ReservedPrefix",
	},
	{
		label: "the pub/ command prefix",
		topic: "pub/prices",
		code: "ReservedPrefix",
	},
	{
		label: "the end/ command prefix",
		topic: "end/prices",
		code: "ReservedPrefix",
	},
] as const;

describe("Topic.parse", () => {
	it.each(VALID_NAMES)("accepts $label", ({ topic }) => {
		expect(Topic.parse(topic).name).toBe(topic);
	});

	it.each(INVALID_NAMES)("rejects $label as $code", ({ topic, code }) => {
		const refusal = expect.objectContaining({ code });
		expect(() => Topic.parse(topic)).toThrow(TopicError);
		expect(() => Topic.parse(topic)).toThrow(refusal);
	});

	it("a topic past the generated limit is refused", () => {
		const overlong = `${LONGEST}a`;
		const refusal = expect.objectContaining({ code: "TooLong" });

		expect(() => Topic.parse(overlong)).toThrow(refusal);
	});

	it("passes a parsed topic through", () => {
		const topic = Topic.parse("prices");

		expect(Topic.parse(topic)).toBe(topic);
	});

	it("refuses with a TypeError, so a catch of the base class matches", () => {
		expect(() => Topic.parse("")).toThrow(TypeError);
	});
});

describe("Command.parse", () => {
	it("an end id parses back to its topic", () => {
		const parsed = Command.parse("end/prices");

		expect(parsed?.completed?.name).toBe("prices");
	});

	it("reads a topic update as no command", () => {
		const parsed = Command.parse("prices");

		expect(parsed).toBeUndefined();
	});
});
