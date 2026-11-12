//! Topic names and their validation. The page `docs/pubsub.md` (Topics)
//! states the rules.

use core::error::Error;
use core::fmt;
use core::str::{from_utf8, FromStr, Utf8Error};
use std::sync::Arc;

/// The prefix a client subscribes with: `sub/<topic>`.
pub const SUB_PREFIX: &str = "sub/";

/// The prefix a client unsubscribes with: `unsub/<topic>`.
pub const UNSUB_PREFIX: &str = "unsub/";

/// The prefix a client publishes with: `pub/<topic>`.
pub const PUB_PREFIX: &str = "pub/";

/// The prefix the registry completes a topic with: `end/<topic>`.
pub const END_PREFIX: &str = "end/";

/// A command verb, named by the prefix of the frame id that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verb {
	/// A client subscribes: `sub/<topic>`.
	Subscribe,
	/// A client unsubscribes: `unsub/<topic>`.
	Unsubscribe,
	/// A client publishes: `pub/<topic>`.
	Publish,
	/// The registry completes a topic: `end/<topic>`.
	End,
}

impl Verb {
	/// Every verb, each of whose prefixes a topic name may not start with.
	pub(crate) const ALL: [Self; 4] = [Self::Subscribe, Self::Unsubscribe, Self::Publish, Self::End];

	/// The prefix of the frame id of this verb.
	pub(crate) const fn prefix(self) -> &'static str {
		match self {
			Self::Subscribe => SUB_PREFIX,
			Self::Unsubscribe => UNSUB_PREFIX,
			Self::Publish => PUB_PREFIX,
			Self::End => END_PREFIX,
		}
	}

	/// The name of this verb in an audit record: its prefix without the `/`.
	pub(crate) fn tag(self) -> &'static str {
		let prefix = self.prefix();
		prefix.trim_end_matches('/')
	}
}

/// A validated topic name: non-empty UTF-8 of at most [`Topic::MAX_LEN`]
/// octets that starts outside every command prefix, matched exactly.
///
/// The name sits behind an `Arc`, so a clone shares it.
///
/// # Sources
///
/// - MQTT 5.0 § 4.7, Topic Names and Topic Filters:
///   <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Topic(Arc<str>);

impl Topic {
	/// The longest topic name, in octets of UTF-8.
	///
	/// The registry keeps each subscribed name, and the backplane keeps a
	/// counter for each published name, so this ceiling bounds the memory
	/// one name can hold.
	pub const MAX_LEN: usize = 256;

	/// The name, as the frame id of each update carries it.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl fmt::Display for Topic {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl FromStr for Topic {
	type Err = TopicError;

	/// Parse a topic name from a UTF-8 string.
	///
	/// # Errors
	///
	/// - [`TopicError::Empty`] -- the name has zero length.
	/// - [`TopicError::TooLong`] -- the name holds more than [`Topic::MAX_LEN`] octets.
	/// - [`TopicError::ReservedPrefix`] -- the name starts with a command prefix.
	fn from_str(name: &str) -> Result<Self, Self::Err> {
		if name.is_empty() {
			return Err(TopicError::Empty);
		}
		if name.len() > Self::MAX_LEN {
			return Err(TopicError::TooLong(name.len()));
		}

		let reserved = Verb::ALL.into_iter().find(|verb| name.starts_with(verb.prefix()));
		if let Some(verb) = reserved {
			return Err(TopicError::ReservedPrefix(verb.prefix()));
		}

		Ok(Self(Arc::from(name)))
	}
}

impl TryFrom<&str> for Topic {
	type Error = TopicError;

	fn try_from(name: &str) -> Result<Self, Self::Error> {
		name.parse()
	}
}

impl TryFrom<&[u8]> for Topic {
	type Error = TopicError;

	/// Parse a topic name from raw octets.
	///
	/// # Errors
	///
	/// - [`TopicError::NotUtf8`] -- the octets are not valid UTF-8.
	/// - The errors of [`from_str`](FromStr::from_str).
	fn try_from(name: &[u8]) -> Result<Self, Self::Error> {
		let text = from_utf8(name)?;
		text.parse()
	}
}

impl From<Utf8Error> for TopicError {
	fn from(cause: Utf8Error) -> Self {
		Self::NotUtf8(cause)
	}
}

/// Why a topic name failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopicError {
	/// The name is empty.
	Empty,
	/// The name holds more than [`Topic::MAX_LEN`] octets. The field is its
	/// length in octets.
	TooLong(usize),
	/// The name starts with a reserved command prefix.
	ReservedPrefix(&'static str),
	/// The name bytes are not valid UTF-8.
	NotUtf8(Utf8Error),
}

impl fmt::Display for TopicError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Empty => f.write_str("a topic name must be non-empty"),
			Self::TooLong(len) => {
				let max = Topic::MAX_LEN;
				write!(f, "a topic name must fit in {max} octets, and this one holds {len}")
			}
			Self::NotUtf8(cause) => write!(f, "a topic name must be UTF-8: {cause}"),
			Self::ReservedPrefix(prefix) => {
				write!(f, "a topic name must not start with the reserved prefix {prefix}")
			}
		}
	}
}

impl Error for TopicError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::NotUtf8(cause) => Some(cause),
			_ => None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Parse `name`, expecting a valid topic.
	fn parsed(name: &str) -> Topic {
		name.parse().expect("the name should parse as a topic")
	}

	#[test]
	fn accepts_hierarchical_names() {
		let topic = parsed("prices/spot/BTC");
		assert_eq!(topic.as_str(), "prices/spot/BTC");
		assert_eq!(topic.to_string(), "prices/spot/BTC");
	}

	#[test]
	fn accepts_names_containing_reserved_words_after_the_start() {
		let topic = parsed("orders/sub/updates");
		assert_eq!(topic.as_str(), "orders/sub/updates");
	}

	#[test]
	fn rejects_an_empty_name() {
		let outcome: Result<Topic, TopicError> = "".parse();
		assert!(matches!(outcome, Err(TopicError::Empty)));
	}

	/// Parse `name`, expecting the reserved prefix that refuses it.
	fn refused_prefix(name: &str) -> Option<&'static str> {
		let outcome: Result<Topic, TopicError> = name.parse();
		match outcome {
			Err(TopicError::ReservedPrefix(prefix)) => Some(prefix),
			_ => None,
		}
	}

	#[test]
	fn rejects_the_subscribe_prefix() {
		assert_eq!(refused_prefix("sub/prices"), Some(SUB_PREFIX));
	}

	#[test]
	fn rejects_the_unsubscribe_prefix() {
		assert_eq!(refused_prefix("unsub/prices"), Some(UNSUB_PREFIX));
	}

	#[test]
	fn rejects_the_publish_prefix() {
		assert_eq!(refused_prefix("pub/prices"), Some(PUB_PREFIX));
	}

	#[test]
	fn rejects_the_end_prefix() {
		assert_eq!(refused_prefix("end/prices"), Some(END_PREFIX));
	}

	#[test]
	fn a_verb_tags_audit_records_with_its_prefix() {
		assert_eq!(Verb::Unsubscribe.tag(), "unsub");
	}

	#[test]
	fn rejects_non_utf8_bytes() {
		let outcome = Topic::try_from([0xff, 0xfe].as_slice());
		assert!(matches!(outcome, Err(TopicError::NotUtf8(_))));
	}

	#[test]
	fn accepts_a_name_at_the_length_ceiling() {
		let name = "x".repeat(Topic::MAX_LEN);
		let outcome: Result<Topic, TopicError> = name.parse();
		assert!(outcome.is_ok());
	}

	#[test]
	fn rejects_a_name_past_the_length_ceiling() {
		let name = "x".repeat(Topic::MAX_LEN + 1);
		let outcome: Result<Topic, TopicError> = name.parse();
		assert!(matches!(outcome, Err(TopicError::TooLong(_))));
	}

	#[test]
	fn parses_from_frame_id_octets() {
		let parsed = Topic::try_from(b"chat/lobby".as_slice());
		assert!(matches!(parsed, Ok(topic) if topic.as_str() == "chat/lobby"));
	}
}
