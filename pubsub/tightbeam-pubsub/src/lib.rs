//! Topic pub/sub for tightbeam multiplexed transports.
//!
//! The registry runs on the existing mux: subscriptions are ordinary
//! client-initiated streams carrying `sub/<topic>` / `unsub/<topic>`
//! command frames, and updates are server-initiated streams whose frame
//! id is the topic.
//!
//! - [`Topic`]: validated names. The command prefixes are reserved.
//! - [`TopicRegistry`]: membership, publish fan-out with dense per-topic
//!   `metadata.order` stamps, and one bounded queue per subscriber so a
//!   slow client never stalls the rest.
//! - [`Backplane`]: sequencing and cross-node distribution behind the
//!   registry. [`Local`] (in-process, the default) covers one node.
//!   Implement the trait over Redis/Postgres/NATS to span nodes without
//!   touching the wire format.
//! - [`PubsubCommands`]: answers the wire commands inside an existing
//!   serve handler, consulting a [`SubscribePolicy`] (and, once
//!   [`with_publish`](PubsubCommands::with_publish) opts in, a
//!   [`PublishPolicy`] for client `pub/<topic>` commands).
//! - [`serve_connection`]: the whole per-connection ceremony in one
//!   call: drivers, registration, command dispatch, application
//!   fallthrough, cleanup.
//! - [`quiesce`](TopicRegistry::quiesce): completes every topic with an
//!   `end/<topic>` push, then refuses new work, so the caller can drain
//!   connections with an orderly closure analog.
//!
//! # Sources
//!
//! - RFC 6455 § 5.5.1, Close frame semantics (orderly closure analog):
//!   <https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.1>
//!
//! The TypeScript counterpart (`@wahidgroup/tightbeam-pubsub-client`)
//! consumes updates with the same conventions: see the extension README
//! for the wire table.

mod backplane;
mod dispatch;
mod frame;
mod policy;
mod registry;
mod serve;
mod topic;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use backplane::{Backplane, BackplaneError, DeliverError, Local, UpdateSink};
pub use dispatch::PubsubCommands;
pub use frame::opaque_payload;
pub use policy::{
	AccessVerdict, AllowAll, DeliveryPolicy, DeliveryVerdict, DropOldest, PublishPolicy, SubscribePolicy,
};
pub use registry::{ConnectionId, PublishError, RegisterError, RegistryOptions, SubscriberId, TopicRegistry};
pub use serve::{serve_connection, serve_connection_as, unrouted, AppRoutes, ConnectionContext};
pub use topic::{Topic, TopicError, END_PREFIX, PUB_PREFIX, SUB_PREFIX, UNSUB_PREFIX};
