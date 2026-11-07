//! Render the pub/sub wire contract as the JSON the TypeScript client imports.
//!
//! Rust [`Topic`] and the command prefixes are the one home of the wire
//! constants. This entry prints them to standard output, and
//! `make -C pubsub client` writes that output to
//! `pubsub/client/src/wire.generated.json` before `tsc` compiles the client.
//!
//! The JSON holds two members:
//!
//! - `topicMaxLen`: [`Topic::MAX_LEN`], the longest topic name in UTF-8 octets.
//! - `prefixes`: the command prefix of each wire verb, keyed `subscribe`,
//!   `unsubscribe`, `publish`, and `end`.

use std::error::Error;

use serde_json::json;
use tightbeam_pubsub::{Topic, END_PREFIX, PUB_PREFIX, SUB_PREFIX, UNSUB_PREFIX};

fn main() -> Result<(), Box<dyn Error>> {
	let contract = json!({
		"topicMaxLen": Topic::MAX_LEN,
		"prefixes": {
			"subscribe": SUB_PREFIX,
			"unsubscribe": UNSUB_PREFIX,
			"publish": PUB_PREFIX,
			"end": END_PREFIX,
		},
	});

	let rendered = serde_json::to_string_pretty(&contract)?;
	println!("{rendered}");
	Ok(())
}
