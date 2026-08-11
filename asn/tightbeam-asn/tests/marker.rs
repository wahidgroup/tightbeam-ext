//! Integration check that `#[derive(AsnCodec)]` implements the marker.

use der::asn1::{
	Any, BitString, BmpString, GeneralizedTime, Ia5String, Null, ObjectIdentifier, OctetString, PrintableString,
	SequenceOf, SetOf, SetOfVec, TeletexString, UtcTime,
};

use tightbeam_asn::AsnCodec;

#[derive(AsnCodec)]
struct Fixture {
	#[allow(dead_code)]
	title: String,
}

#[derive(AsnCodec)]
#[repr(u8)]
#[allow(dead_code)]
enum Status {
	Ok = 0,
	Invalid = 1,
}

#[derive(AsnCodec)]
struct Body {
	#[allow(dead_code)]
	pad: u8,
}

#[derive(AsnCodec)]
#[allow(dead_code)]
enum Request {
	List(Body),
}

#[derive(AsnCodec)]
struct OptionalError {
	#[allow(dead_code)]
	error: Option<Status>,
}

#[derive(AsnCodec)]
struct RecordRow {
	#[allow(dead_code)]
	subject: String,
}

#[derive(AsnCodec)]
struct RecordList {
	#[allow(dead_code)]
	records: Vec<RecordRow>,
}

#[derive(AsnCodec)]
struct LeafMarker {
	#[allow(dead_code)]
	flag: bool,
	#[allow(dead_code)]
	empty: Null,
	#[allow(dead_code)]
	i8_value: i8,
	#[allow(dead_code)]
	u16_value: u16,
	#[allow(dead_code)]
	i32_value: i32,
	#[allow(dead_code)]
	u32_value: u32,
	#[allow(dead_code)]
	u64_value: u64,
	#[allow(dead_code)]
	i64_value: i64,
	#[allow(dead_code)]
	ia5: Ia5String,
	#[allow(dead_code)]
	printable: PrintableString,
	#[allow(dead_code)]
	teletex: TeletexString,
	#[allow(dead_code)]
	bmp: BmpString,
	#[allow(dead_code)]
	octets: OctetString,
	#[allow(dead_code)]
	bits: BitString,
	#[allow(dead_code)]
	oid: ObjectIdentifier,
	#[allow(dead_code)]
	any: Any,
	#[allow(dead_code)]
	utc: UtcTime,
	#[allow(dead_code)]
	generalized: GeneralizedTime,
}

#[derive(AsnCodec)]
struct NestMarker {
	#[allow(dead_code)]
	nested: Option<Vec<Option<u8>>>,
	#[allow(dead_code)]
	tags: SetOfVec<String>,
	#[allow(dead_code)]
	triple: SequenceOf<u8, 3>,
	#[allow(dead_code)]
	pair: SetOf<u8, 2>,
}

fn assert_codec<T: AsnCodec>() {}

#[test]
fn fixture_implements_asn_codec() {
	assert_codec::<Fixture>();
	assert_codec::<Status>();
	assert_codec::<Body>();
	assert_codec::<Request>();
	assert_codec::<OptionalError>();
	assert_codec::<RecordList>();
	assert_codec::<LeafMarker>();
	assert_codec::<NestMarker>();
}
