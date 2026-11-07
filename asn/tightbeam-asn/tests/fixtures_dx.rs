//! Fixture wire types prove AsnCodec Sequence, Enumerated, and Choice shapes.

use core::fmt::Debug;

use der::asn1::{OctetString, SetOfVec};
use der::{Decode, Encode};

#[allow(dead_code)]
mod fixtures;

use fixtures::{
	sample_leaf_bundle, sample_nest_bundle, Ack, Doc, Envelope, ListPad, ListResult, NestBundle, Record, RegisterBody,
	Request, Status, StatusReport,
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
