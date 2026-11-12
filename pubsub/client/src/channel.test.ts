import { describe, expect, it } from "vitest";

import { PullChannel } from "./channel.js";

describe("PullChannel", () => {
	it("delivers items in FIFO order", async () => {
		const channel = new PullChannel<string>();
		void channel.put("one");
		void channel.put("two");

		const first = await channel.next();
		const second = await channel.next();
		expect([first.value, second.value]).toEqual(["one", "two"]);
	});

	it("holds the producer until the consumer takes the item", async () => {
		const channel = new PullChannel<string>();
		const settled: string[] = [];
		const settle = async (offered: Promise<void>, label: string): Promise<void> => {
			await offered;
			settled.push(label);
		};
		const first = settle(channel.put("one"), "put one");
		const second = settle(channel.put("two"), "put two");

		await channel.next();
		await first;
		settled.push("took one");
		await channel.next();
		await second;

		expect(settled).toEqual(["put one", "took one", "put two"]);
	});

	it("hands a waiting consumer the item as it arrives", async () => {
		const channel = new PullChannel<string>();
		const taken = channel.next();

		await channel.put("live");

		expect(await taken).toEqual({ value: "live", done: false });
	});

	it("drains queued items before reporting done", async () => {
		const channel = new PullChannel<string>();
		void channel.put("last");
		channel.finish();

		const drained = await channel.next();
		expect(drained).toEqual({ value: "last", done: false });

		const done = await channel.next();
		expect(done.done).toBe(true);
	});

	it("resolves waiting consumers with done on finish", async () => {
		const channel = new PullChannel<string>();
		const waiting = channel.next();

		channel.finish();

		expect((await waiting).done).toBe(true);
	});

	it("queues nothing once finished", async () => {
		const channel = new PullChannel<string>();
		channel.finish();

		await channel.put("late");

		expect(await channel.next()).toEqual({ value: undefined, done: true });
	});

	it("releases a parked producer on finish", async () => {
		const channel = new PullChannel<string>();
		const offered = channel.put("parked");

		channel.finish();

		await offered;
		expect(await channel.next()).toEqual({ value: "parked", done: false });
	});

	it("still drains an item whose producer finish released", async () => {
		const channel = new PullChannel<string>();
		void channel.put("parked");
		channel.finish();

		const drained = await channel.next();
		expect(drained).toEqual({ value: "parked", done: false });
	});
});
