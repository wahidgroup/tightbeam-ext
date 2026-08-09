import { describe, expect, it, vi } from "vitest";

import type * as Wasm from "#wasm";
import type { Frame, TransportError } from "./index.js";
import {
	TRANSPORT_ERROR_NAME,
	TightbeamWsClient,
	frame,
	initClient,
	isTransportError,
} from "./index.js";

/*
 * The wasm socket is faked at the module boundary so these tests pin the TS
 * integration path: the exact work DER crosses the boundary unmodified, the
 * abort signal reaches the signal-aware export, and wasm rejections pass
 * through untouched. The frame codec stays real (importOriginal), so the
 * decode of the returned servlet DER is the production path.
 */

/**
 * The served servlet type the fake gateway answers.
 */
const PING_TARGET = "urn:tightbeam::servlet:ping";

/**
 * Recorded wasm-boundary call: which export ran and with what bytes.
 */
interface RecordedCall {
	method: "submitWork" | "submitWorkWithSignal";
	target: string;
	workDer: Uint8Array;
}

const harness = vi.hoisted(() => {
	const state: {
		calls: RecordedCall[];
		replyDer: Uint8Array;
		rejection: Error | undefined;
	} = {
		calls: [],
		replyDer: new Uint8Array(),
		rejection: undefined,
	};
	return state;
});

vi.mock("#wasm", async (importOriginal) => {
	const actual = await importOriginal<typeof Wasm>();

	class FakeMuxWsClient {
		readonly closed = new Promise<never>(() => {
			/* never settles: the fake session stays open */
		});
		readonly readyState = 1;

		static connect(): Promise<FakeMuxWsClient> {
			return Promise.resolve(new FakeMuxWsClient());
		}

		close(): void {
			/* no wasm resources to release */
		}

		free(): void {
			/* no wasm resources to release */
		}

		submitWork(target: string, workDer: Uint8Array): Promise<Uint8Array> {
			harness.calls.push({ method: "submitWork", target, workDer });
			if (harness.rejection !== undefined) {
				return Promise.reject(harness.rejection);
			}

			return Promise.resolve(harness.replyDer);
		}

		submitWorkWithSignal(
			target: string,
			workDer: Uint8Array,
			signal: AbortSignal,
		): Promise<Uint8Array> {
			harness.calls.push({
				method: "submitWorkWithSignal",
				target,
				workDer,
			});

			return new Promise((_resolve, reject) => {
				if (signal.aborted) {
					reject(new Error("aborted before dispatch"));
					return;
				}

				signal.addEventListener("abort", () => {
					reject(signal.reason);
				});
			});
		}
	}

	// The module shape is untyped at the mock boundary, so the fake replaces
	// the class without asserting structural identity with the wasm one.
	return {
		...actual,
		MuxWsClient: FakeMuxWsClient,
	};
});

await initClient();

/**
 * A signed end-to-end work frame, built through the real codec.
 */
async function workFrame(): Promise<Frame> {
	const built = await frame()
		.withId("work-1")
		.withOrder(7n)
		.withMessage(new Uint8Array([21]))
		.build();
	return built;
}

/**
 * A servlet reply frame distinct from the work frame.
 */
async function replyFrame(): Promise<Frame> {
	const built = await frame()
		.withId("work-1")
		.withOrder(8n)
		.withMessage(new Uint8Array([42]))
		.build();
	return built;
}

/**
 * The rejection shape the wasm layer throws for a gateway refusal.
 */
function workRefusal(): Error {
	const failure = new Error("Work refused: Unavailable");
	failure.name = TRANSPORT_ERROR_NAME;
	Object.assign(failure, { code: "WorkRefused", status: "Unavailable" });
	return failure;
}

async function connectFake(): Promise<TightbeamWsClient> {
	const client = await TightbeamWsClient.connect(
		"ws://127.0.0.1:1",
		new Uint8Array(1),
	);
	return client;
}

/**
 * Awaits `submission`, requiring a transport-error rejection carrying
 * `code`, and returns the rejection for follow-up property assertions.
 */
async function expectTransportRejection(
	submission: Promise<unknown>,
	code: string,
): Promise<TransportError> {
	let outcome: unknown;
	try {
		await submission;
		outcome = undefined;
	} catch (error: unknown) {
		outcome = error;
	}

	if (!isTransportError(outcome)) {
		throw new Error(
			`expected a transport-error rejection, got ${String(outcome)}`,
		);
	}

	expect(outcome.code).toBe(code);
	return outcome;
}

describe("submitWork", () => {
	it("resolves with the decoded servlet frame and passes the work DER through byte-for-byte", async () => {
		const work = await workFrame();
		const reply = await replyFrame();
		harness.rejection = undefined;
		harness.replyDer = reply.toDer();

		const client = await connectFake();
		const served = await client.submitWork(PING_TARGET, work);

		expect(served.toDer()).toEqual(reply.toDer());

		const call = harness.calls.at(-1);
		expect(call?.method).toBe("submitWork");
		expect(call?.target).toBe(PING_TARGET);
		expect(call?.workDer).toEqual(work.toDer());
	});

	it("routes an abort signal to the signal-aware export and rejects with the abort reason", async () => {
		const work = await workFrame();
		harness.rejection = undefined;

		const client = await connectFake();
		const controller = new AbortController();
		const submitted = client.submitWork(PING_TARGET, work, {
			signal: controller.signal,
		});

		const reason = new Error("caller gave up");
		controller.abort(reason);

		await expect(submitted).rejects.toBe(reason);

		const call = harness.calls.at(-1);
		expect(call?.method).toBe("submitWorkWithSignal");
	});

	it("propagates a WorkRefused rejection with its transit status", async () => {
		const work = await workFrame();
		harness.rejection = workRefusal();

		const client = await connectFake();
		const submitted = client.submitWork(
			"urn:tightbeam::servlet:absent",
			work,
		);

		const rejection = await expectTransportRejection(
			submitted,
			"WorkRefused",
		);
		expect(rejection).toMatchObject({ status: "Unavailable" });
	});

	it("rejects on a released client without reaching wasm", async () => {
		const work = await workFrame();
		harness.rejection = undefined;

		const client = await connectFake();
		client.close();

		const before = harness.calls.length;
		const submitted = client.submitWork(PING_TARGET, work);

		await expectTransportRejection(submitted, "ConnectionClosed");
		expect(harness.calls.length).toBe(before);
	});
});
