//! wasm32 AsnCodec JS value encode/decode round-trips for fixture types.
#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

use der::asn1::{OctetString, PrintableString, SetOfVec};
use der::{Decode, Encode};
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

use tightbeam_asn::AsnCodec;
use tightbeam_asn_fixtures::{
	sample_leaf_bundle, sample_nest_bundle, Ack, Doc, Envelope, LeafBundle, ListPad, ListResult, NestBundle, Record,
	RegisterBody, Request, Status,
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

#[wasm_bindgen_test]
fn u64_rejects_js_number_accepts_bigint() {
	let mut value = sample_leaf_bundle();
	value.u64_value = 42;

	let Ok(js) = value.to_js() else {
		panic!("to_js");
	};

	set_field(&js, "u64_value", &JsValue::from(42.0));

	let Err(_) = LeafBundle::from_js(&js) else {
		panic!("u64 must reject JS number");
	};

	set_field(&js, "u64_value", &JsValue::from(BigInt::from(42_u64)));

	let Ok(decoded) = LeafBundle::from_js(&js) else {
		panic!("u64 must accept bigint");
	};

	assert_eq!(decoded.u64_value, 42, "u64 bigint");
}

#[wasm_bindgen_test]
fn i64_rejects_js_number_accepts_bigint() {
	let mut value = sample_leaf_bundle();
	value.i64_value = -42;

	let Ok(js) = value.to_js() else {
		panic!("to_js");
	};

	set_field(&js, "i64_value", &JsValue::from(-42.0));

	let Err(_) = LeafBundle::from_js(&js) else {
		panic!("i64 must reject JS number");
	};

	set_field(&js, "i64_value", &JsValue::from(BigInt::from(-42_i64)));

	let Ok(decoded) = LeafBundle::from_js(&js) else {
		panic!("i64 must accept bigint");
	};

	assert_eq!(decoded.i64_value, -42, "i64 bigint");
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

#[wasm_bindgen_test]
fn sequence_of_rejects_wrong_length() {
	let Ok(js) = sample_nest_bundle().to_js() else {
		panic!("to_js");
	};

	let short = Array::new();
	short.push(&JsValue::from(1.0));
	short.push(&JsValue::from(2.0));

	set_field(&js, "triple", &short.into());

	let Err(_) = NestBundle::from_js(&js) else {
		panic!("SequenceOf length 2 must fail for N=3");
	};
}

#[wasm_bindgen_test]
fn set_of_rejects_wrong_length() {
	let Ok(js) = sample_nest_bundle().to_js() else {
		panic!("to_js");
	};

	let one = Array::new();
	one.push(&JsValue::from(1.0));
	set_field(&js, "pair", &one.into());

	let Err(_) = NestBundle::from_js(&js) else {
		panic!("SetOf length 1 must fail for N=2");
	};
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
