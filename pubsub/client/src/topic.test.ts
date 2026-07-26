import { describe, expect, it } from "vitest";

import { assertTopic } from "./topic.js";

const VALID_NAMES = [
	{ label: "a plain name", topic: "prices" },
	{ label: "a hierarchical name", topic: "prices/spot/BTC" },
	{ label: "a reserved word after the start", topic: "orders/sub/updates" },
] as const;

const INVALID_NAMES = [
	{ label: "an empty name", topic: "" },
	{ label: "the sub/ command prefix", topic: "sub/prices" },
	{ label: "the unsub/ command prefix", topic: "unsub/prices" },
	{ label: "the pub/ command prefix", topic: "pub/prices" },
	{ label: "the end/ command prefix", topic: "end/prices" },
] as const;

describe("assertTopic", () => {
	it.each(VALID_NAMES)("accepts $label", ({ topic }) => {
		expect(() => {
			assertTopic(topic);
		}).not.toThrow();
	});

	it.each(INVALID_NAMES)("rejects $label with a TypeError", ({ topic }) => {
		expect(() => {
			assertTopic(topic);
		}).toThrow(TypeError);
	});
});
