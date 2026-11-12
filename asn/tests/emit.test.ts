import { readFile } from "node:fs/promises";

import type { MessageCodec } from "@wahidgroup/tightbeam-ws-client";
import { describe, expect, expectTypeOf, it } from "vitest";

import * as asn from "#asn-wasm";

import { DocSamples } from "../../scripts/vitest/doc-samples.mjs";
import { AsnCodecs } from "./codecs.js";
import type { Doc, LeafBundle, NestBundle, Request, Routed, StatusReport } from "./codecs.js";
import * as asnNode from "./fixture/node/asn_fixtures.js";
import { AsnCodecs as NodeCodecs } from "./fixture/node/codecs.js";

const binary = await readFile(new URL("./fixture/asn_fixtures_bg.wasm", import.meta.url));

/**
 * The emitted codecs, bound to the fixture package that `make test asn` builds beside this suite.
 */
const codecs = new AsnCodecs(asn, asn.initSync({ module: binary }));

/**
 * The value that `codec` decodes from the DER that it encodes for `value`.
 */
function roundTrip<T>(codec: MessageCodec<T>, value: T): T {
	return codec.decode(codec.encode(value));
}

describe("tightbeam-asn-emit", () => {
	it("round-trips a Sequence", () => {
		const doc: Doc = { title: "emit-test" };
		expect(roundTrip(codecs.Doc, doc)).toEqual(doc);
	});

	it("round-trips a Sequence with an Enumerated field", () => {
		const report: StatusReport = { title: "emit-test", status: 2 };
		expect(roundTrip(codecs.StatusReport, report)).toEqual(report);
	});

	it("round-trips each alternative of a Choice", () => {
		const requests: Request[] = [{ Register: { doc: { title: "register" } } }, { List: { pad: 0 } }];
		for (const request of requests) {
			expect(roundTrip(codecs.Request, request)).toEqual(request);
		}
	});

	it("round-trips a Sequence with a Choice field and an Enumerated field under a raw identifier", () => {
		const routed: Routed = { type: 1, request: { List: { pad: 0 } } };
		expect(roundTrip(codecs.Routed, routed)).toEqual(routed);
	});

	it("round-trips every der leaf", () => {
		const leaves: LeafBundle = {
			flag: true,
			empty: null,
			i8_value: -7,
			u16_value: 1000,
			i32_value: -300_000,
			u32_value: 4_000_000_000,
			u64_value: 9_000_000_000_000_000_000n,
			i64_value: -9_000_000_000_000_000_000n,
			ia5: "abc",
			printable: "ABC",
			teletex: "tel",
			bmp: "Bmp",
			bits: { unusedBits: 3, bytes: Uint8Array.of(0b1010_1000) },
			oid: "1.2.840.113549.1.1.1",
			any: Uint8Array.of(0x02, 0x01, 0x01),
			utc: "2024-06-15T12:30:45Z",
			generalized: "2024-06-15T12:30:45Z",
		};
		expect(roundTrip(codecs.LeafBundle, leaves)).toEqual(leaves);
	});

	it("round-trips the OPTIONAL and collection fields", () => {
		const nest: NestBundle = {
			nested: [4, 5],
			deeper: [{ subject: "nested" }],
			tags: ["a", "b"],
			triple: [1, 2, 3],
			pair: [1, 2],
		};
		expect(roundTrip(codecs.NestBundle, nest)).toEqual(nest);
	});

	it("reads null as an absent OPTIONAL", () => {
		const cleared: NestBundle = { nested: null, tags: [], triple: [], pair: [] };
		expect(roundTrip(codecs.NestBundle, cleared)).toStrictEqual({ tags: [], triple: [], pair: [] });
	});

	it("takes the output of the init of the module", () => {
		expectTypeOf<ConstructorParameters<typeof AsnCodecs>[1]>().toEqualTypeOf<asn.InitOutput>();
	});

	it("binds a nodejs build, which initializes on import, from its exports alone", () => {
		const nodeCodecs = new NodeCodecs(asnNode);
		const doc: Doc = { title: "node" };
		expect(roundTrip(nodeCodecs.Doc, doc)).toEqual(doc);
	});

	it("compiles the README quick start against the emitted module", () => {
		const samples = new DocSamples({
			suite: import.meta.url,
			tsconfig: "./tsconfig.json",
			sources: { "#your-asn-alias": "./fixture/asn_fixtures.d.ts" },
		});

		expect(samples.diagnostics({ page: "../tightbeam-asn/README.md" })).toEqual([]);
	}, 60_000);
});
