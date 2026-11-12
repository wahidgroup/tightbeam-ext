//! The DER oracle of the fixture DER types, as tightbeam scenarios:
//! [docs/asn.md][tests].
//!
//! [tests]: https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#tests
#![cfg(not(target_arch = "wasm32"))]

use der::asn1::{OctetString, SetOfVec};
use der::{Decode, Encode};
use tightbeam::testing::SetupEnv;
use tightbeam::trace::TraceCollector;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};

#[allow(dead_code)]
mod fixtures;

use fixtures::{
	sample_leaf_bundle, sample_nest_bundle, Ack, Doc, Envelope, ListPad, ListResult, NestBundle, Record, RegisterBody,
	Request, Routed, Status, StatusReport,
};

/// Whether one value decoded from its DER equal to itself.
const ROUND_TRIP: Urn<'static> = urn!("test", "event:asn-fixtures/der-round-trip");

/// Round-trip `value` through DER, and record on `trace` whether the decode
/// equals it.
fn round_trip<T>(trace: &TraceCollector, value: T) -> Result<(), TightBeamError>
where
	T: PartialEq + Encode + for<'a> Decode<'a>,
{
	let der = value.to_der()?;
	let decoded = T::from_der(&der)?;
	trace.event_with(ROUND_TRIP, &[], decoded == value)?;
	Ok(())
}

tb_assert_spec! {
	pub SequenceSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(ROUND_TRIP, exactly!(8), equals!(true))
		]
	}
}

// Every Sequence shape round-trips: a plain one, a nested one, one with an
// enumerated field, one with a Choice field, an absent and a present optional,
// and an empty and a filled list.
tb_scenario! {
	name: sequence_der_round_trips,
	spec: SequenceSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| -> Result<(), TightBeamError> {
			round_trip(&trace, Doc { title: "typed-body".into() })?;

			let payload = OctetString::new([1_u8, 2, 3])?;
			round_trip(&trace, Envelope { doc: Doc { title: "nested".into() }, payload })?;
			round_trip(&trace, StatusReport { title: "csr".into(), status: Status::RateLimited })?;
			round_trip(&trace, Routed { r#type: Status::Ok, request: Request::List(ListPad { pad: 0 }) })?;
			round_trip(&trace, Ack { error: None })?;
			round_trip(&trace, Ack { error: Some(Status::InvalidRequest) })?;
			round_trip(&trace, ListResult { records: Vec::new() })?;
			round_trip(&trace, ListResult { records: vec![Record { subject: "alice".into() }, Record { subject: "bob".into() }] })?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub EnumeratedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(ROUND_TRIP, exactly!(3), equals!(true))
		]
	}
}

// Every variant of the Enumerated shape round-trips.
tb_scenario! {
	name: enumerated_der_round_trips,
	spec: EnumeratedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| -> Result<(), TightBeamError> {
			for status in [Status::Ok, Status::InvalidRequest, Status::RateLimited] {
				round_trip(&trace, status)?;
			}
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ChoiceSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(ROUND_TRIP, exactly!(2), equals!(true))
		]
	}
}

// Every alternative of the Choice shape round-trips.
tb_scenario! {
	name: choice_der_round_trips,
	spec: ChoiceSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| -> Result<(), TightBeamError> {
			for request in [Request::Register(RegisterBody { doc: Doc { title: "leaf".into() } }), Request::List(ListPad { pad: 0 })] {
				round_trip(&trace, request)?;
			}
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub LeafAndNestSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(ROUND_TRIP, exactly!(3), equals!(true))
		]
	}
}

// The leaf bundle, the nest bundle, and a nest bundle with its optionals
// absent and its set empty all round-trip.
tb_scenario! {
	name: leaf_and_nest_der_round_trips,
	spec: LeafAndNestSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| -> Result<(), TightBeamError> {
			round_trip(&trace, sample_leaf_bundle())?;
			round_trip(&trace, sample_nest_bundle())?;

			let nest = sample_nest_bundle();
			round_trip(&trace, NestBundle { nested: None, deeper: None, tags: SetOfVec::new(), triple: nest.triple, pair: nest.pair })?;
			Ok(())
		}
	}
}
