//! Fixture wire types prove AsnCodec Sequence, Enumerated, Choice, and TS emit.

use core::fmt::Debug;

use der::asn1::{OctetString, SetOfVec};
use der::{Decode, Encode};
use tightbeam_asn_fixtures::{
	all_codecs_ts, sample_leaf_bundle, sample_nest_bundle, Ack, Doc, Envelope, LeafBundle, ListPad, ListResult,
	NestBundle, Record, RegisterBody, Request, Status, StatusReport,
};

fn assert_der_round_trip<T>(value: T)
where
	T: Clone + Debug + PartialEq + Encode + for<'a> Decode<'a>,
{
	let Ok(der) = value.to_der() else {
		panic!("encode DER");
	};
	let Ok(decoded) = T::from_der(&der) else {
		panic!("decode DER");
	};

	assert_eq!(decoded, value, "DER round-trip");
}

#[test]
fn sequence_der_round_trips() {
	assert_der_round_trip(Doc { title: "typed-body".into() });

	let Ok(payload) = OctetString::new([1_u8, 2, 3]) else {
		panic!("build payload octets");
	};

	assert_der_round_trip(Envelope { doc: Doc { title: "nested".into() }, payload });
	assert_der_round_trip(StatusReport { title: "csr".into(), status: Status::RateLimited });
	assert_der_round_trip(Ack { error: None });
	assert_der_round_trip(Ack { error: Some(Status::InvalidRequest) });
	assert_der_round_trip(ListResult { records: Vec::new() });
	assert_der_round_trip(ListResult {
		records: vec![Record { subject: "alice".into() }, Record { subject: "bob".into() }],
	});
}

#[test]
fn enumerated_der_round_trips() {
	for status in [Status::Ok, Status::InvalidRequest, Status::RateLimited] {
		assert_der_round_trip(status);
	}
}

#[test]
fn choice_der_round_trips() {
	for request in [
		Request::Register(RegisterBody { doc: Doc { title: "leaf".into() } }),
		Request::List(ListPad { pad: 0 }),
	] {
		assert_der_round_trip(request);
	}
}

#[test]
fn leaf_and_nest_der_round_trips() {
	assert_der_round_trip(sample_leaf_bundle());
	assert_der_round_trip(sample_nest_bundle());
	assert_der_round_trip(NestBundle {
		nested: None,
		deeper: None,
		tags: SetOfVec::new(),
		triple: sample_nest_bundle().triple,
		pair: sample_nest_bundle().pair,
	});
}

#[test]
fn all_codecs_ts_contains_expected_fragments() {
	let source = all_codecs_ts();
	for needle in [
		"import type { MessageCodec } from \"@wahidgroup/tightbeam-ws-client\"",
		"MessageCodec<Doc>",
		"MessageCodec<Envelope>",
		"MessageCodec<Status>",
		"MessageCodec<StatusReport>",
		"MessageCodec<ListPad>",
		"MessageCodec<RegisterBody>",
		"MessageCodec<Request>",
		"MessageCodec<Ack>",
		"MessageCodec<ListResult>",
		"MessageCodec<Record>",
		"MessageCodec<LeafBundle>",
		"MessageCodec<NestBundle>",
		"export type Status = number;",
		"export type Request =",
		"| { Register: RegisterBody }",
		"| { List: ListPad }",
		"export interface Doc {",
		"export interface Envelope {",
		"payload: Uint8Array;",
		"export interface StatusReport {",
		"status: Status;",
		"export interface ListPad {",
		"export interface RegisterBody {",
		"export interface Ack {",
		"error?: Status | null;",
		"export interface ListResult {",
		"records: Record[];",
		"export interface Record {",
		"export interface LeafBundle {",
		"flag: boolean;",
		"empty: null;",
		"u64_value: bigint;",
		"i64_value: bigint;",
		"bits: { unusedBits: number; bytes: Uint8Array }",
		"export interface NestBundle {",
		"nested?: number[] | null;",
		"deeper?: Record[] | null;",
		"tags: string[];",
		"triple: number[];",
		"pair: number[];",
	] {
		assert!(source.contains(needle), "missing fragment: {needle}");
	}
	let _ = (LeafBundle::ASN_CODEC_TS, NestBundle::ASN_CODEC_TS);
}
