#![doc = include_str!("../README.md")]

// This module compiles every Rust example of the page under `docs/` that
// specifies this crate as a doctest, so a renamed item fails the build
// instead of leaving the page stale.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/pubsub.md")]
mod docs_pubsub {}

mod backplane;
mod dispatch;
mod emit;
mod frame;
mod policy;
mod registry;
mod serve;
mod topic;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use backplane::{Backplane, BackplaneFault, DeliverError, Local, NodeSink, UpdateSink};
pub use dispatch::PubsubCommands;
pub use emit::{Emitter, LinkLost, Settled};
pub use policy::{
	AccessVerdict, AllowAll, DeliveryPolicy, DeliveryVerdict, DropOldest, PublishPolicy, SubscribePolicy,
};
pub use registry::{
	ConnectionId, EmitDeadline, PublishError, RegisterError, RegistryOptions, RegistryView, SubscriberId, TopicRegistry,
};
pub use serve::{AppRoutes, ConnectionContext, Unrouted};
pub use topic::{Topic, TopicError, END_PREFIX, PUB_PREFIX, SUB_PREFIX, UNSUB_PREFIX};
