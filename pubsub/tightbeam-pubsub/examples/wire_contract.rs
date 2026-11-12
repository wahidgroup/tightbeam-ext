//! Render the pub/sub command contract as the JSON that the TypeScript
//! client imports. The page `docs/pubsub.md` (Command convention) lists it.

use std::error::Error;

use serde_json::{json, Value};
use tightbeam_pubsub::{Topic, END_PREFIX, PUB_PREFIX, SUB_PREFIX, UNSUB_PREFIX};

/// U+FEFF, the byte order mark, which leads one accepted sample name.
const BYTE_ORDER_MARK: char = match char::from_u32(0xFEFF) {
	Some(mark) => mark,
	None => panic!("U+FEFF is a Unicode scalar value"),
};

/// One sample topic name, and the `TopicError` code that refuses it, or
/// `None` for a name that both validations accept.
struct Sample {
	name: String,
	refusal: Option<&'static str>,
}

impl Sample {
	/// The sample names that both the Rust and the TypeScript suites grade.
	fn all() -> Vec<Self> {
		let accepted = |name: &str| Self { name: name.to_owned(), refusal: None };
		let refused = |name: &str, code| Self { name: name.to_owned(), refusal: Some(code) };
		let longest = "a".repeat(Topic::MAX_LEN);
		let longest_wide = "§".repeat(Topic::MAX_LEN / 2);
		let marked = format!("{BYTE_ORDER_MARK}prices");

		vec![
			accepted("prices"),
			accepted("prices/spot/BTC"),
			accepted("orders/sub/updates"),
			accepted("prices/😀"),
			accepted(&marked),
			accepted(&longest),
			accepted(&longest_wide),
			refused("", "Empty"),
			refused(&format!("{longest}a"), "TooLong"),
			refused(&format!("{longest_wide}§"), "TooLong"),
			refused("sub/prices", "ReservedPrefix"),
			refused("unsub/prices", "ReservedPrefix"),
			refused("pub/prices", "ReservedPrefix"),
			refused("end/prices", "ReservedPrefix"),
		]
	}

	/// This sample as the JSON the client reads.
	fn rendered(&self) -> Value {
		json!({ "name": self.name, "refusal": self.refusal })
	}
}

fn main() -> Result<(), Box<dyn Error>> {
	let samples: Vec<Value> = Sample::all().iter().map(Sample::rendered).collect();
	let contract = json!({
		"topicMaxLen": Topic::MAX_LEN,
		"prefixes": {
			"subscribe": SUB_PREFIX,
			"unsubscribe": UNSUB_PREFIX,
			"publish": PUB_PREFIX,
			"end": END_PREFIX,
		},
		"samples": samples,
	});

	let rendered = serde_json::to_string_pretty(&contract)?;
	println!("{rendered}");
	Ok(())
}

#[cfg(test)]
mod tests {
	use tightbeam_pubsub::TopicError;

	use super::*;

	/// The code of `refusal`, as the variant of [`TopicError`] that names it.
	fn code(refusal: &TopicError) -> &'static str {
		match refusal {
			TopicError::Empty => "Empty",
			TopicError::TooLong(_) => "TooLong",
			TopicError::ReservedPrefix(_) => "ReservedPrefix",
			TopicError::NotUtf8(_) => "NotUtf8",
		}
	}

	#[test]
	fn the_topic_parse_answers_every_sample_name() {
		for sample in Sample::all() {
			let parsed: Result<Topic, TopicError> = sample.name.parse();
			let refusal = parsed.err().as_ref().map(code);
			assert_eq!(refusal, sample.refusal, "the sample {:?}", sample.name);
		}
	}
}
