//! wasm32 AsnCodec JS value encode/decode round-trips for fixture types.
#![cfg(target_arch = "wasm32")]

use der::asn1::{OctetString, PrintableString, SequenceOf, SetOfVec};
use der::{Decode, Encode};
use js_sys::{Array, BigInt, Object, Reflect, TypeError, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

use tightbeam_asn::{AsnCodec, FieldError};

#[allow(dead_code)]
mod fixtures;

use fixtures::{
	sample_leaf_bundle, sample_nest_bundle, Ack, Doc, Envelope, LeafBundle, ListPad, ListResult, NestBundle, Record,
	RegisterBody, Request, Routed, Status,
};

fn assert_js_round_trip<T>(value: &T)
where
	T: AsnCodec + Clone + PartialEq + core::fmt::Debug + Encode + for<'a> Decode<'a>,
{
	let Ok(js) = value.to_js() else {
		panic!("to_js");
	};
	let Ok(from_js) = T::from_js(&js) else {
		panic!("from_js after to_js");
	};

	assert_eq!(&from_js, value, "to_js/from_js");

	let Ok(der) = from_js.to_der() else {
		panic!("to_der");
	};
	let Ok(decoded) = T::from_der(&der) else {
		panic!("from_der");
	};
	let Ok(decoded_js) = decoded.to_js() else {
		panic!("to_js after from_der");
	};
	let Ok(round) = T::from_js(&decoded_js) else {
		panic!("from_js after encode/decode");
	};

	assert_eq!(round, value.clone(), "JS encode/decode round-trip");
}

fn set_field(object: &JsValue, key: &str, value: &JsValue) {
	let Ok(true) = Reflect::set(object, &JsValue::from_str(key), value) else {
		panic!("Reflect.set {key}");
	};
}

/// `sample` with its `field` set to `value` in JavaScript, then read back.
fn with_field<T: AsnCodec>(sample: &T, field: &str, value: &JsValue) -> Result<T, FieldError> {
	let Ok(js) = sample.to_js() else {
		panic!("to_js");
	};

	set_field(&js, field, value);
	T::from_js(&js)
}

#[wasm_bindgen_test]
fn doc_js_round_trip() {
	assert_js_round_trip(&Doc { title: "typed-body".into() });
}

#[wasm_bindgen_test]
fn status_js_round_trip() {
	for status in [Status::Ok, Status::InvalidRequest, Status::RateLimited] {
		assert_js_round_trip(&status);
	}
}

#[wasm_bindgen_test]
fn request_js_round_trip() {
	assert_js_round_trip(&Request::Register(RegisterBody { doc: Doc { title: "leaf".into() } }));
	assert_js_round_trip(&Request::List(ListPad { pad: 0 }));
}

#[wasm_bindgen_test]
fn routed_js_round_trip() {
	assert_js_round_trip(&Routed { r#type: Status::InvalidRequest, request: Request::List(ListPad { pad: 0 }) });
}

#[wasm_bindgen_test]
fn envelope_js_round_trip() {
	let Ok(payload) = OctetString::new([1_u8, 2, 3]) else {
		panic!("build payload octets");
	};

	assert_js_round_trip(&Envelope { doc: Doc { title: "nested".into() }, payload });
}

#[wasm_bindgen_test]
fn doc_from_plain_js_object() {
	let object = JsValue::from(Object::new());
	set_field(&object, "title", &JsValue::from_str("plain"));
	let Ok(doc) = Doc::from_js(&object) else {
		panic!("Doc::from_js plain object");
	};

	assert_eq!(doc, Doc { title: "plain".into() }, "plain JS Doc");
}

#[wasm_bindgen_test]
fn status_from_js_number() {
	let Ok(status) = Status::from_js(&JsValue::from(2.0)) else {
		panic!("Status::from_js number");
	};

	assert_eq!(status, Status::RateLimited, "Status discriminant");
}

#[wasm_bindgen_test]
fn request_from_externally_tagged_js() {
	let doc = JsValue::from(Object::new());
	set_field(&doc, "title", &JsValue::from_str("leaf"));

	let body = JsValue::from(Object::new());
	set_field(&body, "doc", &doc);

	let tagged = JsValue::from(Object::new());
	set_field(&tagged, "Register", &body);

	let Ok(request) = Request::from_js(&tagged) else {
		panic!("Request::from_js externally tagged");
	};

	assert_eq!(
		request,
		Request::Register(RegisterBody { doc: Doc { title: "leaf".into() } }),
		"externally tagged Register"
	);
}

#[wasm_bindgen_test]
fn envelope_from_plain_js_object() {
	let doc = JsValue::from(Object::new());
	set_field(&doc, "title", &JsValue::from_str("nested"));

	let payload = Uint8Array::from([1_u8, 2, 3].as_slice());
	let object = JsValue::from(Object::new());
	set_field(&object, "doc", &doc);
	set_field(&object, "payload", &payload.into());

	let Ok(envelope) = Envelope::from_js(&object) else {
		panic!("Envelope::from_js plain object");
	};
	let Ok(expected_payload) = OctetString::new([1_u8, 2, 3]) else {
		panic!("build expected payload");
	};

	assert_eq!(
		envelope,
		Envelope { doc: Doc { title: "nested".into() }, payload: expected_payload },
		"plain JS Envelope"
	);
}

#[wasm_bindgen_test]
fn ack_js_round_trip() {
	assert_js_round_trip(&Ack { error: None });
	assert_js_round_trip(&Ack { error: Some(Status::RateLimited) });
}

#[wasm_bindgen_test]
fn list_result_js_round_trip() {
	assert_js_round_trip(&ListResult { records: Vec::new() });
	assert_js_round_trip(&ListResult {
		records: vec![Record { subject: "alice".into() }, Record { subject: "bob".into() }],
	});
}

#[wasm_bindgen_test]
fn ack_optional_from_js_nullish() {
	let absent = JsValue::from(Object::new());
	let Ok(from_absent) = Ack::from_js(&absent) else {
		panic!("Ack::from_js absent key");
	};

	assert_eq!(from_absent, Ack { error: None }, "absent error key");

	let with_null = JsValue::from(Object::new());
	set_field(&with_null, "error", &JsValue::NULL);

	let Ok(from_null) = Ack::from_js(&with_null) else {
		panic!("Ack::from_js null");
	};

	assert_eq!(from_null, Ack { error: None }, "null error");

	let with_undefined = JsValue::from(Object::new());
	set_field(&with_undefined, "error", &JsValue::UNDEFINED);

	let Ok(from_undefined) = Ack::from_js(&with_undefined) else {
		panic!("Ack::from_js undefined");
	};

	assert_eq!(from_undefined, Ack { error: None }, "undefined error");

	let with_status = JsValue::from(Object::new());
	set_field(&with_status, "error", &JsValue::from(1.0));

	let Ok(from_status) = Ack::from_js(&with_status) else {
		panic!("Ack::from_js Status number");
	};

	assert_eq!(
		from_status,
		Ack { error: Some(Status::InvalidRequest) },
		"present Enumerated error"
	);
}

#[wasm_bindgen_test]
fn ack_to_js_omits_none_error() {
	let Ok(js) = (Ack { error: None }).to_js() else {
		panic!("Ack::to_js None");
	};
	let Ok(false) = Reflect::has(&js, &JsValue::from_str("error")) else {
		panic!("None error must omit key");
	};
}

#[wasm_bindgen_test]
fn list_result_from_plain_js_arrays() {
	let empty = JsValue::from(Object::new());
	set_field(&empty, "records", &Array::new().into());

	let Ok(empty_result) = ListResult::from_js(&empty) else {
		panic!("ListResult::from_js empty array");
	};

	assert_eq!(empty_result, ListResult { records: Vec::new() }, "empty records");

	let alice = JsValue::from(Object::new());
	set_field(&alice, "subject", &JsValue::from_str("alice"));

	let records = Array::new();
	records.push(&alice);

	let populated = JsValue::from(Object::new());
	set_field(&populated, "records", &records.into());

	let Ok(list) = ListResult::from_js(&populated) else {
		panic!("ListResult::from_js nested records");
	};

	assert_eq!(
		list,
		ListResult { records: vec![Record { subject: "alice".into() }] },
		"non-empty records"
	);
}

#[wasm_bindgen_test]
fn leaf_bundle_js_round_trip() {
	assert_js_round_trip(&sample_leaf_bundle());
}

#[wasm_bindgen_test]
fn nest_bundle_js_round_trip() {
	assert_js_round_trip(&sample_nest_bundle());
	assert_js_round_trip(&NestBundle {
		nested: None,
		deeper: None,
		tags: SetOfVec::new(),
		triple: sample_nest_bundle().triple,
		pair: sample_nest_bundle().pair,
	});
}

#[wasm_bindgen_test]
fn leaf_bundle_from_plain_js_object() {
	let expected = sample_leaf_bundle();
	let Ok(js) = expected.to_js() else {
		panic!("LeafBundle::to_js");
	};
	let Ok(decoded) = LeafBundle::from_js(&js) else {
		panic!("LeafBundle::from_js");
	};

	assert_eq!(decoded, expected, "plain JS LeafBundle");

	let Ok(der) = decoded.to_der() else {
		panic!("LeafBundle to_der");
	};
	let Ok(from_der) = LeafBundle::from_der(&der) else {
		panic!("LeafBundle from_der");
	};

	assert_eq!(from_der, expected, "LeafBundle der oracle");
}

/// The refusal of a `u64_value` that is no bigint in the u64 range.
const U64_REFUSAL: &str = "u64_value: expected a bigint in the u64 range";

/// The refusal of an `i64_value` that is no bigint in the i64 range.
const I64_REFUSAL: &str = "i64_value: expected a bigint in the i64 range";

#[wasm_bindgen_test]
fn a_u64_refuses_a_number() {
	let read = with_field(&sample_leaf_bundle(), "u64_value", &JsValue::from(42.0));

	let refusal = read.err().map(|error| error.to_string());
	assert_eq!(refusal.as_deref(), Some(U64_REFUSAL));
}

#[wasm_bindgen_test]
fn a_u64_refuses_a_bigint_below_zero() {
	let below = BigInt::from(-1_i64);
	let read = with_field(&sample_leaf_bundle(), "u64_value", &JsValue::from(below));

	let refusal = read.err().map(|error| error.to_string());
	assert_eq!(refusal.as_deref(), Some(U64_REFUSAL));
}

#[wasm_bindgen_test]
fn a_u64_refuses_a_bigint_past_its_maximum() {
	let past = BigInt::from(u128::from(u64::MAX) + 1);
	let read = with_field(&sample_leaf_bundle(), "u64_value", &JsValue::from(past));

	let refusal = read.err().map(|error| error.to_string());
	assert_eq!(refusal.as_deref(), Some(U64_REFUSAL));
}

#[wasm_bindgen_test]
fn a_u64_takes_zero() {
	let read = with_field(&sample_leaf_bundle(), "u64_value", &JsValue::from(BigInt::from(0_u64)));

	assert_eq!(read.map(|bundle| bundle.u64_value), Ok(0));
}

#[wasm_bindgen_test]
fn a_u64_takes_its_maximum() {
	let read = with_field(&sample_leaf_bundle(), "u64_value", &JsValue::from(BigInt::from(u64::MAX)));

	assert_eq!(read.map(|bundle| bundle.u64_value), Ok(u64::MAX));
}

#[wasm_bindgen_test]
fn an_i64_refuses_a_number() {
	let read = with_field(&sample_leaf_bundle(), "i64_value", &JsValue::from(-42.0));

	let refusal = read.err().map(|error| error.to_string());
	assert_eq!(refusal.as_deref(), Some(I64_REFUSAL));
}

#[wasm_bindgen_test]
fn an_i64_refuses_a_bigint_below_its_minimum() {
	let below = BigInt::from(i128::from(i64::MIN) - 1);
	let read = with_field(&sample_leaf_bundle(), "i64_value", &JsValue::from(below));

	let refusal = read.err().map(|error| error.to_string());
	assert_eq!(refusal.as_deref(), Some(I64_REFUSAL));
}

#[wasm_bindgen_test]
fn an_i64_refuses_a_bigint_past_its_maximum() {
	let past = BigInt::from(i128::from(i64::MAX) + 1);
	let read = with_field(&sample_leaf_bundle(), "i64_value", &JsValue::from(past));

	let refusal = read.err().map(|error| error.to_string());
	assert_eq!(refusal.as_deref(), Some(I64_REFUSAL));
}

#[wasm_bindgen_test]
fn an_i64_takes_its_minimum() {
	let read = with_field(&sample_leaf_bundle(), "i64_value", &JsValue::from(BigInt::from(i64::MIN)));

	assert_eq!(read.map(|bundle| bundle.i64_value), Ok(i64::MIN));
}

#[wasm_bindgen_test]
fn an_i64_takes_its_maximum() {
	let read = with_field(&sample_leaf_bundle(), "i64_value", &JsValue::from(BigInt::from(i64::MAX)));

	assert_eq!(read.map(|bundle| bundle.i64_value), Ok(i64::MAX));
}

#[wasm_bindgen_test]
fn bitstring_preserves_unused_bits() {
	let value = sample_leaf_bundle();
	assert_eq!(value.bits.unused_bits(), 3, "fixture unused bits");
	assert_js_round_trip(&value);

	let Ok(js) = value.to_js() else {
		panic!("to_js");
	};
	let Ok(bits) = Reflect::get(&js, &JsValue::from_str("bits")) else {
		panic!("bits field");
	};
	let Ok(unused) = Reflect::get(&bits, &JsValue::from_str("unusedBits")) else {
		panic!("unusedBits");
	};

	assert_eq!(unused.as_f64(), Some(3.0), "unusedBits projected");
}

/// A JS `Array` of the integers from 1 to `length`.
fn integers(length: u8) -> JsValue {
	let array = Array::new();
	for number in 1..=length {
		array.push(&JsValue::from(f64::from(number)));
	}

	array.into()
}

/// A `NestBundle` whose `field` holds the integers from 1 to `length`.
fn bundle_with(field: &str, length: u8) -> Result<NestBundle, FieldError> {
	with_field(&sample_nest_bundle(), field, &integers(length))
}

/// `field` takes `length` elements and round-trips them.
fn assert_holds(field: &str, length: u8) {
	let Ok(bundle) = bundle_with(field, length) else {
		panic!("{field} of {length} elements is within its bound");
	};

	assert_js_round_trip(&bundle);
}

/// `field` refuses `length` elements and names itself.
fn assert_overflows(field: &str, length: u8) {
	let Err(error) = bundle_with(field, length) else {
		panic!("{field} of {length} elements is over its bound");
	};

	assert!(error.to_string().starts_with(field), "{error}");
}

#[wasm_bindgen_test]
fn a_sequence_of_three_takes_none() {
	assert_holds("triple", 0);
}

#[wasm_bindgen_test]
fn a_sequence_of_three_takes_two() {
	assert_holds("triple", 2);
}

#[wasm_bindgen_test]
fn a_sequence_of_three_takes_three() {
	assert_holds("triple", 3);
}

#[wasm_bindgen_test]
fn a_sequence_of_three_refuses_four() {
	assert_overflows("triple", 4);
}

#[wasm_bindgen_test]
fn a_set_of_two_takes_none() {
	assert_holds("pair", 0);
}

#[wasm_bindgen_test]
fn a_set_of_two_takes_one() {
	assert_holds("pair", 1);
}

#[wasm_bindgen_test]
fn a_set_of_two_takes_two() {
	assert_holds("pair", 2);
}

#[wasm_bindgen_test]
fn a_set_of_two_refuses_three() {
	assert_overflows("pair", 3);
}

#[wasm_bindgen_test]
fn a_short_wire_collection_decodes_and_encodes_again() {
	let short = NestBundle { triple: SequenceOf::new(), ..sample_nest_bundle() };
	let Ok(der) = short.to_der() else {
		panic!("to_der");
	};
	let Ok(decoded) = NestBundle::from_der(&der) else {
		panic!("from_der");
	};

	assert_js_round_trip(&decoded);
}

#[wasm_bindgen_test]
fn a_failure_names_its_field() {
	let result = ListResult { records: vec![Record { subject: "a".into() }, Record { subject: "b".into() }] };
	let Ok(js) = result.to_js() else {
		panic!("to_js");
	};

	let records = Array::from(&Reflect::get(&js, &"records".into()).unwrap_or(JsValue::UNDEFINED));
	set_field(&records.get(1), "subject", &JsValue::from(7.0));

	let Err(error) = ListResult::from_js(&js) else {
		panic!("a number is not a subject");
	};
	assert_eq!(error.to_string(), "records[1].subject: expected a string");
}

#[wasm_bindgen_test]
fn a_missing_field_is_named() {
	let Err(error) = Doc::from_js(&Object::new().into()) else {
		panic!("a Doc needs a title");
	};

	assert_eq!(error.to_string(), "title: expected a string");
}

#[wasm_bindgen_test]
fn a_value_that_is_no_object_fails_at_the_value() {
	let Err(error) = Doc::from_js(&JsValue::from(5.0)) else {
		panic!("a number is not a Doc");
	};

	assert_eq!(error.to_string(), "expected an object");
}

#[wasm_bindgen_test]
fn a_bit_string_that_is_no_object_fails_at_its_field() {
	let Ok(js) = sample_leaf_bundle().to_js() else {
		panic!("to_js");
	};

	set_field(&js, "bits", &JsValue::from(5.0));

	let Err(error) = LeafBundle::from_js(&js) else {
		panic!("a number is not a BIT STRING");
	};
	assert_eq!(error.to_string(), "bits: expected an object");
}

#[wasm_bindgen_test]
fn an_object_without_a_prototype_is_an_object() {
	let null = JsValue::NULL;
	let prototype: &Object = null.unchecked_ref();
	let bare = Object::create(prototype);
	set_field(&bare, "title", &JsValue::from_str("bare"));

	let Ok(doc) = Doc::from_js(&bare) else {
		panic!("a null-prototype object carries fields");
	};
	assert_eq!(doc.title, "bare");
}

#[wasm_bindgen_test]
fn a_key_of_the_prototype_is_no_field() {
	let prototype = Object::new();
	set_field(&prototype, "error", &JsValue::from(1.0));
	let inherited = Object::create(&prototype);

	let Ok(ack) = Ack::from_js(&inherited) else {
		panic!("an inherited error is an absent OPTIONAL");
	};
	assert_eq!(ack, Ack { error: None });
}

#[wasm_bindgen_test]
fn a_shape_failure_throws_a_type_error() {
	let Err(error) = Doc::from_js(&Object::new().into()) else {
		panic!("a Doc needs a title");
	};

	assert!(JsValue::from(error).has_type::<TypeError>());
}

#[wasm_bindgen_test]
fn a_choice_failure_names_its_variant() {
	let register = Object::new();
	set_field(&register, "Register", &Object::new());

	let Err(error) = Request::from_js(&register) else {
		panic!("Register needs a doc");
	};

	assert!(error.to_string().starts_with("Register.doc"), "{error}");
}

#[wasm_bindgen_test]
fn printable_string_rejects_illegal_code_point() {
	let Err(_) = PrintableString::new("bad@") else {
		panic!("der PrintableString constructor must reject @");
	};
	let Ok(js) = sample_leaf_bundle().to_js() else {
		panic!("to_js");
	};

	set_field(&js, "printable", &JsValue::from_str("bad@"));

	let Err(_) = LeafBundle::from_js(&js) else {
		panic!("AsnCodec must reject illegal PrintableString via der");
	};
}

#[wasm_bindgen_test]
fn oid_and_any_and_times_from_js() {
	let expected = sample_leaf_bundle();
	let Ok(js) = expected.to_js() else {
		panic!("to_js");
	};
	let Ok(decoded) = LeafBundle::from_js(&js) else {
		panic!("from_js");
	};

	assert_eq!(decoded.oid, expected.oid, "oid");
	assert_eq!(decoded.any, expected.any, "any");
	assert_eq!(decoded.utc, expected.utc, "utc");
	assert_eq!(decoded.generalized, expected.generalized, "generalized");
}
