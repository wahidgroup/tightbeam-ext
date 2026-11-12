import { describe, expect, it } from "vitest";

import { Push, Topic, TopicError } from "./topic.js";
import WIRE from "./wire.generated.json" with { type: "json" };

/**
 * The sample names that the Rust suite grades too, each with the code that
 * refuses it, or `null` for an accepted name.
 */
const SAMPLES = WIRE.samples;

/**
 * The sample names that both validations accept.
 */
const ACCEPTED = SAMPLES.filter(({ refusal }) => refusal === null);

const UTF8 = new TextEncoder();

/**
 * The names that UTF-16 holds and UTF-8 does not, which only this suite
 * grades.
 */
const LONE_SURROGATES = [
	{ label: "a lone high surrogate", topic: "prices\uD800" },
	{ label: "a lone low surrogate", topic: "\uDC00prices" },
] as const;

describe("Topic.parse", () => {
	it.each(SAMPLES)("answers the sample $name with $refusal", ({ name, refusal }) => {
		if (refusal === null) {
			expect(Topic.parse(name).name).toBe(name);
			return;
		}

		const refused = expect.objectContaining({ code: refusal });
		expect(() => Topic.parse(name)).toThrow(TopicError);
		expect(() => Topic.parse(name)).toThrow(refused);
	});

	it.each(LONE_SURROGATES)("rejects $label as NotUtf8", ({ topic }) => {
		const refused = expect.objectContaining({ code: "NotUtf8" });
		expect(() => Topic.parse(topic)).toThrow(refused);
	});

	it("passes a parsed topic through", () => {
		const topic = Topic.parse("prices");
		expect(Topic.parse(topic)).toBe(topic);
	});

	it("refuses with a TypeError, so a catch of the base class matches", () => {
		expect(() => Topic.parse("")).toThrow(TypeError);
	});
});

describe("Push.parse", () => {
	it("an end id parses as the completion of its topic", () => {
		const parsed = Push.parse(UTF8.encode("end/prices"));
		expect(parsed?.kind).toBe("end");
		expect(parsed?.topic.name).toBe("prices");
	});

	it("a topic name parses as an update of that topic", () => {
		const parsed = Push.parse(UTF8.encode("prices"));
		expect(parsed?.kind).toBe("update");
		expect(parsed?.topic.name).toBe("prices");
	});

	it.each(ACCEPTED)("the octets of the sample $name parse as an update of that exact name", ({ name }) => {
		const parsed = Push.parse(UTF8.encode(name));
		expect(parsed?.topic.name).toBe(name);
	});

	it.each(["sub/prices", "end/", ""])("the id %j names no topic", (id) => {
		expect(Push.parse(UTF8.encode(id))).toBeUndefined();
	});

	it("an id whose octets are not UTF-8 names no topic", () => {
		const id = Uint8Array.of(0xff, ...UTF8.encode("prices"));
		expect(Push.parse(id)).toBeUndefined();
	});
});
