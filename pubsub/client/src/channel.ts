/**
 * The pull bridge between push delivery and async iteration.
 *
 * The manager delivers updates one at a time and awaits each delivery
 * before acknowledging the stream. `put` resolves only when the
 * consumer takes the item, so an un-iterated subscription back-pressures
 * the server's delivery lane exactly like a slow handler.
 */

/**
 * A single-consumer FIFO whose producer awaits consumption.
 */
export class PullChannel<I> {
	private readonly items: { item: I; taken: () => void }[] = [];

	private readonly takers: ((result: IteratorResult<I>) => void)[] = [];

	private done = false;

	/**
	 * Offer one item, resolving once the consumer takes it. After
	 * {@link finish}, resolves immediately: nobody is coming.
	 */
	async put(item: I): Promise<void> {
		if (this.done) {
			return;
		}

		const taker = this.takers.shift();
		if (taker !== undefined) {
			taker({ value: item, done: false });
			return;
		}

		await new Promise<void>((taken) => {
			this.items.push({ item, taken: () => taken() });
		});
	}

	/**
	 * End the stream: queued items still drain, then every `next` call
	 * resolves done. Idempotent.
	 *
	 * Parked producers release immediately - their delivery (and the
	 * stream acknowledgment behind it) must settle even if nobody ever
	 * takes the item.
	 */
	finish(): void {
		this.done = true;
		for (const parked of this.items) {
			parked.taken();
		}
		for (const taker of this.takers.splice(0)) {
			taker({ value: undefined, done: true });
		}
	}

	/**
	 * Take the next item, or a done result once the channel finished
	 * and drained.
	 */
	async next(): Promise<IteratorResult<I>> {
		const queued = this.items.shift();
		if (queued !== undefined) {
			queued.taken();
			return { value: queued.item, done: false };
		}
		if (this.done) {
			return { value: undefined, done: true };
		}

		return new Promise<IteratorResult<I>>((resolve) => {
			this.takers.push(resolve);
		});
	}
}
