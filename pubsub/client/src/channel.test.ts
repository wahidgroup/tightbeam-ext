import { describe, expect, it } from "vitest";

import { PullChannel } from "./channel.js";

/**
 * Whether `promise` settled once the microtask queue drained, observed
 * without awaiting it: the marker arrives on a macrotask, so a promise
 * resolved any number of microtask hops earlier still wins the race.
 */
async function settled(promise: Promise<unknown>): Promise<boolean> {
	const MARKER = Symbol("pending");
	const marker = new Promise<symbol>((resolve) => {
		setTimeout(() => {
			resolve(MARKER);
		}, 0);
	});

	const outcome = await Promise.race([promise, marker]);
	return outcome !== MARKER;
}

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

		const offered = channel.put("held");
		expect(await settled(offered)).toBe(false);

		await channel.next();

		expect(await settled(offered)).toBe(true);
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

	it("releases producers immediately once finished", async () => {
		const channel = new PullChannel<string>();
		channel.finish();

		const offered = channel.put("late");
		expect(await settled(offered)).toBe(true);
	});

	it("releases a parked producer on finish", async () => {
		const channel = new PullChannel<string>();
		const offered = channel.put("parked");

		channel.finish();

		expect(await settled(offered)).toBe(true);
	});

	it("still drains an item whose producer finish released", async () => {
		const channel = new PullChannel<string>();
		void channel.put("parked");
		channel.finish();

		const drained = await channel.next();
		expect(drained).toEqual({ value: "parked", done: false });
	});
});
