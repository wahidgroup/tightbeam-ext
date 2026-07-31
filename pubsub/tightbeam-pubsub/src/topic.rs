//! Topic names and their validation.
//!
//! A topic is a non-empty UTF-8 string with an optional `/`-separated
//! hierarchy. Matching is exact: no wildcards, no shared subscriptions.
//! The wire command prefixes are reserved so a topic can never be mistaken
//! for a command.
//!
//! # Sources
//!
//! - MQTT 5.0 § 4.7, Topic Names and Topic Filters:
//!   <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>
//!

use core::fmt;
use core::str::{from_utf8, FromStr, Utf8Error};
use std::error::Error;
use std::sync::Arc;

/// Wire prefix a client subscribes with: `sub/<topic>`.
pub const SUB_PREFIX: &str = "sub/";

/// Wire prefix a client unsubscribes with: `unsub/<topic>`.
pub const UNSUB_PREFIX: &str = "unsub/";

/// Wire prefix a client publishes with: `pub/<topic>`.
pub const PUB_PREFIX: &str = "pub/";

/// Wire prefix the registry completes a topic with: `end/<topic>`.
pub const END_PREFIX: &str = "end/";

/// Every reserved command prefix, in dispatch order.
const RESERVED_PREFIXES: [&str; 4] = [SUB_PREFIX, UNSUB_PREFIX, PUB_PREFIX, END_PREFIX];

/// A validated topic name: non-empty UTF-8, exact-match semantics,
/// never starting with a reserved command prefix.
///
/// Clone-cheap (`Arc` inner) so registries and managers key maps with it
/// without copying the name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Topic(Arc<str>);

impl Topic {
	/// The topic name as a string slice.
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl AsRef<str> for Topic {
	fn as_ref(&self) -> &str {
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
	/// - [`TopicError::Empty`]: the name has zero length.
	/// - [`TopicError::ReservedPrefix`]: the name starts with a wire command prefix.
	fn from_str(name: &str) -> Result<Self, Self::Err> {
		if name.is_empty() {
			return Err(TopicError::Empty);
		}

		for prefix in RESERVED_PREFIXES {
			if name.starts_with(prefix) {
				return Err(TopicError::ReservedPrefix(prefix));
			}
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
	/// - [`TopicError::NotUtf8`]: the octets are not valid UTF-8.
	/// - [`TopicError::Empty`] / [`TopicError::ReservedPrefix`]: same as [`FromStr`].
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
	/// The name starts with a reserved wire command prefix.
	ReservedPrefix(&'static str),
	/// The name bytes are not valid UTF-8.
	NotUtf8(Utf8Error),
}

impl fmt::Display for TopicError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Empty => f.write_str("a topic name must be non-empty"),
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
		assert_eq!(topic.as_ref(), "orders/sub/updates");
	}

	#[test]
	fn rejects_an_empty_name() {
		let outcome: Result<Topic, TopicError> = "".parse();
		assert!(matches!(outcome, Err(TopicError::Empty)));
	}

	#[test]
	fn rejects_every_reserved_command_prefix() {
		for prefix in RESERVED_PREFIXES {
			let outcome: Result<Topic, TopicError> = format!("{prefix}prices").parse();
			assert!(matches!(outcome, Err(TopicError::ReservedPrefix(rejected)) if rejected == prefix));
		}
	}

	#[test]
	fn rejects_non_utf8_bytes() {
		let outcome = Topic::try_from([0xff, 0xfe].as_slice());
		assert!(matches!(outcome, Err(TopicError::NotUtf8(_))));
	}

	#[test]
	fn parses_from_wire_bytes() {
		let parsed = Topic::try_from(b"chat/lobby".as_slice());
		assert!(matches!(parsed, Ok(topic) if topic.as_str() == "chat/lobby"));
	}
}
