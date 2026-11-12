#![doc = include_str!("../README.md")]

// This module compiles every Rust sample of `docs/pubsub.md` as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/pubsub.md")]
mod docs_pubsub {}

mod audit;
mod backplane;
mod dispatch;
mod emit;
pub mod events;
mod frame;
mod policy;
mod registry;
mod serve;
mod topic;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use backplane::{Backplane, BackplaneFault, DeliverError, Local, PublishError};
pub use dispatch::PubsubCommands;
pub use emit::{EmitDeadline, Emitter, LinkLost, Settled};
pub use frame::OpaqueFrame;
pub use policy::{
	AccessVerdict, AllowAll, DeliveryPolicy, DeliveryVerdict, DropOldest, PublishPolicy, SubscribePolicy,
};
pub use registry::{Delivered, Drained, NodeSink, RegistryOptions, RegistryView, TopicRegistry};
pub use serve::{AppRoutes, ConnectionContext, Unrouted};
pub use topic::{Topic, TopicError, END_PREFIX, PUB_PREFIX, SUB_PREFIX, UNSUB_PREFIX};
