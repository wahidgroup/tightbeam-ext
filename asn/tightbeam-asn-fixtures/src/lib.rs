//! Fixture `der` messages for `AsnCodec` encode and decode exports.

use der::asn1::{
	Any, BitString, BmpString, GeneralizedTime, Ia5String, Null, ObjectIdentifier, OctetString,
	PrintableString, SequenceOf, SetOf, SetOfVec, TeletexString, UtcTime,
};
use der::{Choice, DateTime, Enumerated, Sequence, Tag};
use tightbeam_asn::AsnCodec;

/// Minimal document body used by engine tests.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, AsnCodec)]
#[asn_codec(js_name = "Doc")]
pub struct Doc {
	/// UTF-8 title carried as the Sequence string field.
	pub title: String,
}

/// Nested envelope used to exercise AsnCodec field recursion.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, AsnCodec)]
#[asn_codec(js_name = "Envelope")]
pub struct Envelope {
	/// Nested document Sequence carried inside the envelope.
	pub doc: Doc,
	/// Opaque octet payload beside the nested document.
	pub payload: OctetString,
}

/// Outcome discriminant matching CSR status shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated, AsnCodec)]
#[repr(u8)]
#[asn_codec(js_name = "Status")]
pub enum Status {
	Ok = 0,
	InvalidRequest = 1,
	RateLimited = 2,
}

/// Sequence carrying a nested Enumerated field.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, AsnCodec)]
#[asn_codec(js_name = "StatusReport")]
pub struct StatusReport {
	/// UTF-8 title carried beside the status discriminant.
	pub title: String,
	/// Nested Enumerated outcome projected as a JS number.
	pub status: Status,
}

/// Empty list query pad (INTEGER) for Choice coverage.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, AsnCodec, Default)]
#[asn_codec(js_name = "ListPad")]
pub struct ListPad {
	/// INTEGER pad required by the List Choice payload shape.
	pub pad: u8,
}

/// Nested register payload for Choice coverage.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, AsnCodec)]
#[asn_codec(js_name = "RegisterBody")]
pub struct RegisterBody {
	/// Nested document Sequence for the Register Choice variant.
	pub doc: Doc,
}

/// Request Choice with pad Sequence and nested Sequence variants.
#[derive(Clone, Debug, Eq, PartialEq, Choice, AsnCodec)]
#[asn_codec(js_name = "Request")]
pub enum Request {
	#[asn1(context_specific = "0", constructed = "true")]
	Register(RegisterBody),
	#[asn1(context_specific = "1", constructed = "true")]
	List(ListPad),
}

/// Nested identity-shaped Sequence for list-result fixture coverage.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, AsnCodec)]
#[asn_codec(js_name = "Record")]
pub struct Record {
	/// UTF-8 subject name for the nested list element.
	pub subject: String,
}

/// Ack-shaped Sequence with an OPTIONAL Enumerated error.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, AsnCodec)]
#[asn_codec(js_name = "Ack")]
pub struct Ack {
	/// OPTIONAL Enumerated error omitted when the ack succeeds.
	pub error: Option<Status>,
}

/// List-result Sequence carrying SEQUENCE OF nested records.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, AsnCodec)]
#[asn_codec(js_name = "ListResult")]
pub struct ListResult {
	/// Nested Sequence elements for the list result body.
	pub records: Vec<Record>,
}

/// Sequence exercising der-owned AsnCodec leaf field vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, AsnCodec)]
#[asn_codec(js_name = "LeafBundle")]
pub struct LeafBundle {
	/// BOOLEAN leaf projected as a JS boolean.
	pub flag: bool,
	/// NULL leaf projected as JS null.
	pub empty: Null,
	/// INTEGER leaf in the inclusive i8 range.
	pub i8_value: i8,
	/// INTEGER leaf in the inclusive u16 range.
	pub u16_value: u16,
	/// INTEGER leaf in the inclusive i32 range.
	pub i32_value: i32,
	/// INTEGER leaf in the inclusive u32 range.
	pub u32_value: u32,
	/// INTEGER leaf requiring a JS bigint.
	pub u64_value: u64,
	/// INTEGER leaf requiring a JS bigint.
	pub i64_value: i64,
	/// IA5String leaf validated by the der constructor.
	pub ia5: Ia5String,
	/// PrintableString leaf validated by the der constructor.
	pub printable: PrintableString,
	/// TeletexString leaf validated by the der constructor.
	pub teletex: TeletexString,
	/// BmpString leaf validated by the der constructor.
	pub bmp: BmpString,
	/// BIT STRING leaf with unused-bit count and raw bytes.
	pub bits: BitString,
	/// OBJECT IDENTIFIER leaf as a dotted string.
	pub oid: ObjectIdentifier,
	/// ANY leaf carrying opaque DER bytes.
	pub any: Any,
	/// UTCTime leaf as an RFC 3339 string.
	pub utc: UtcTime,
	/// GeneralizedTime leaf as an RFC 3339 string.
	pub generalized: GeneralizedTime,
}

/// Sequence exercising recursive containers and SET/SEQUENCE OF shapes.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, AsnCodec)]
#[asn_codec(js_name = "NestBundle")]
pub struct NestBundle {
	/// OPTIONAL SEQUENCE OF INTEGER values.
	pub nested: Option<Vec<u8>>,
	/// OPTIONAL SEQUENCE OF nested Sequence values.
	pub deeper: Option<Vec<Record>>,
	/// SET OF UTF-8 strings as a JS Array.
	pub tags: SetOfVec<String>,
	/// Fixed-length SEQUENCE OF INTEGER values.
	pub triple: SequenceOf<u8, 3>,
	/// Fixed-length SET OF INTEGER values.
	pub pair: SetOf<u8, 2>,
}

/// Build a LeafBundle with stable der-valid leaf values for oracle tests.
pub fn sample_leaf_bundle() -> LeafBundle {
	let Ok(ia5) = Ia5String::new("abc") else {
		panic!("ia5");
	};
	let Ok(printable) = PrintableString::new("ABC") else {
		panic!("printable");
	};
	let Ok(teletex) = TeletexString::new("tel") else {
		panic!("teletex");
	};
	let Ok(bmp) = BmpString::from_utf8("Bmp") else {
		panic!("bmp");
	};
	let Ok(bits) = BitString::new(3, [0b1010_1000_u8]) else {
		panic!("bits");
	};
	let Ok(oid) = ObjectIdentifier::new("1.2.840.113549.1.1.1") else {
		panic!("oid");
	};
	let Ok(any) = Any::new(Tag::Integer, [0x01_u8]) else {
		panic!("any");
	};
	let Ok(datetime) = DateTime::new(2024, 6, 15, 12, 30, 45) else {
		panic!("datetime");
	};
	let Ok(utc) = UtcTime::from_date_time(datetime) else {
		panic!("utc");
	};
	LeafBundle {
		flag: true,
		empty: Null,
		i8_value: -7,
		u16_value: 1000,
		i32_value: -300_000,
		u32_value: 4_000_000_000,
		u64_value: 9_000_000_000_000_000_000,
		i64_value: -9_000_000_000_000_000_000,
		ia5,
		printable,
		teletex,
		bmp,
		bits,
		oid,
		any,
		utc,
		generalized: GeneralizedTime::from_date_time(datetime),
	}
}

/// Build a NestBundle with nested Option/Vec and SET/SEQUENCE OF values.
pub fn sample_nest_bundle() -> NestBundle {
	let Ok(tags) = SetOfVec::try_from(vec![String::from("a"), String::from("b")]) else {
		panic!("tags");
	};
	let mut triple = SequenceOf::new();
	let Ok(()) = triple.add(1) else {
		panic!("triple 1");
	};
	let Ok(()) = triple.add(2) else {
		panic!("triple 2");
	};
	let Ok(()) = triple.add(3) else {
		panic!("triple 3");
	};
	let Ok(pair) = SetOf::try_from([1_u8, 2_u8]) else {
		panic!("pair");
	};
	NestBundle {
		nested: Some(vec![1, 2, 3]),
		deeper: Some(vec![Record { subject: "nested".into() }]),
		tags,
		triple,
		pair,
	}
}

const CODECS_TS_HEADER: &str = concat!(
	"import type { MessageCodec } from \"@wahidgroup/tightbeam-ws-client\";\n",
	"\n",
	"import {\n",
	"\tdecodeAck,\n",
	"\tdecodeDoc,\n",
	"\tdecodeEnvelope,\n",
	"\tdecodeLeafBundle,\n",
	"\tdecodeListPad,\n",
	"\tdecodeListResult,\n",
	"\tdecodeNestBundle,\n",
	"\tdecodeRecord,\n",
	"\tdecodeRegisterBody,\n",
	"\tdecodeRequest,\n",
	"\tdecodeStatus,\n",
	"\tdecodeStatusReport,\n",
	"\tencodeAck,\n",
	"\tencodeDoc,\n",
	"\tencodeEnvelope,\n",
	"\tencodeLeafBundle,\n",
	"\tencodeListPad,\n",
	"\tencodeListResult,\n",
	"\tencodeNestBundle,\n",
	"\tencodeRecord,\n",
	"\tencodeRegisterBody,\n",
	"\tencodeRequest,\n",
	"\tencodeStatus,\n",
	"\tencodeStatusReport,\n",
	"} from \"./tightbeam_asn_fixtures.js\";\n\n",
);

/// Concatenated thin TypeScript MessageCodec module for fixture types.
pub fn all_codecs_ts() -> String {
	[
		CODECS_TS_HEADER,
		Doc::ASN_CODEC_TS,
		"\n",
		Envelope::ASN_CODEC_TS,
		"\n",
		Status::ASN_CODEC_TS,
		"\n",
		StatusReport::ASN_CODEC_TS,
		"\n",
		ListPad::ASN_CODEC_TS,
		"\n",
		RegisterBody::ASN_CODEC_TS,
		"\n",
		Request::ASN_CODEC_TS,
		"\n",
		Record::ASN_CODEC_TS,
		"\n",
		Ack::ASN_CODEC_TS,
		"\n",
		ListResult::ASN_CODEC_TS,
		"\n",
		LeafBundle::ASN_CODEC_TS,
		"\n",
		NestBundle::ASN_CODEC_TS,
		"\n",
	]
	.concat()
}
