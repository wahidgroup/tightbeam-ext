//! The events of the audit trail of a served connection. The page
//! `docs/pubsub.md` (Connection serve) states the label and value of each.

use tightbeam::urn;
use tightbeam::urn::Urn;

/// The registry admitted the connection.
pub const CONNECTION_ADMITTED: Urn<'static> = urn!("tightbeam-pubsub", "event:connection/admitted");

/// The connection left the registry, because its serve ended or the registry
/// expelled it.
pub const CONNECTION_LEFT: Urn<'static> = urn!("tightbeam-pubsub", "event:connection/left");

/// The registry expelled the connection, ahead of its departure: the delivery
/// policy voted it off, an update emit counted as the end of the link
/// ([`LinkLost`]), or a drain dismissed it.
///
/// [`LinkLost`]: crate::LinkLost
pub const CONNECTION_EXPELLED: Urn<'static> = urn!("tightbeam-pubsub", "event:connection/expelled");

/// A command took no effect.
pub const COMMAND_REFUSED: Urn<'static> = urn!("tightbeam-pubsub", "event:command/refused");

/// A subscription dropped an update: the delivery policy dropped it from a
/// full queue, or the peer refused it, or the budget of the session could not
/// carry it.
pub const UPDATE_DROPPED: Urn<'static> = urn!("tightbeam-pubsub", "event:update/dropped");
