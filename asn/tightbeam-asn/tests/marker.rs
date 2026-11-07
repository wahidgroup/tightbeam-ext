//! Integration check that `#[derive(AsnCodec)]` implements the marker off
//! `wasm32`, where the expansion needs no der derive.
#![cfg(not(target_arch = "wasm32"))]
#![allow(dead_code)]

use der::asn1::{
	Any, BitString, BmpString, GeneralizedTime, Ia5String, Null, ObjectIdentifier, OctetString, PrintableString,
	SequenceOf, SetOf, SetOfVec, TeletexString, UtcTime,
};

use tightbeam_asn::AsnCodec;

#[derive(AsnCodec)]
struct Fixture {
	title: String,
}

#[derive(AsnCodec)]
#[repr(u8)]
enum Status {
	Ok = 0,
	Invalid = 1,
}

#[derive(AsnCodec)]
#[repr(u8)]
enum ImplicitStatus {
	Ok,
	Invalid,
}

#[derive(AsnCodec)]
struct Body {
	pad: u8,
}

#[derive(AsnCodec)]
enum Request {
	List(Body),
}

#[derive(AsnCodec)]
struct OptionalError {
	error: Option<Status>,
}

#[derive(AsnCodec)]
struct RecordRow {
	subject: String,
}

#[derive(AsnCodec)]
struct RecordList {
	records: Vec<RecordRow>,
}

#[derive(AsnCodec)]
struct LeafMarker {
	flag: bool,
	empty: Null,
	i8_value: i8,
	u16_value: u16,
	i32_value: i32,
	u32_value: u32,
	u64_value: u64,
	i64_value: i64,
	ia5: Ia5String,
	printable: PrintableString,
	teletex: TeletexString,
	bmp: BmpString,
	octets: OctetString,
	bits: BitString,
	oid: ObjectIdentifier,
	any: Any,
	utc: UtcTime,
	generalized: GeneralizedTime,
}

#[derive(AsnCodec)]
struct NestMarker {
	nested: Option<Vec<u8>>,
	tags: SetOfVec<String>,
	triple: SequenceOf<u8, 3>,
	pair: SetOf<u8, 2>,
}

fn assert_codec<T: AsnCodec>() {}

#[test]
fn fixture_implements_asn_codec() {
	assert_codec::<Fixture>();
	assert_codec::<Status>();
	assert_codec::<ImplicitStatus>();
	assert_codec::<Body>();
	assert_codec::<Request>();
	assert_codec::<OptionalError>();
	assert_codec::<RecordList>();
	assert_codec::<LeafMarker>();
	assert_codec::<NestMarker>();
}
