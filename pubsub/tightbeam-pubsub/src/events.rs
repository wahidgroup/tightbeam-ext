//! The events that a served connection records on its audit trail, under the
//! `instrument` feature.
//!
//! A connection records on the trace of the transport that its link was
//! accepted on ([`ServedMux::trace`]), beside the events of its tightbeam
//! session and the gate verdict of each call. A connection whose transport
//! records on no trace, or a build without the feature, records nothing.
//!
//! The label of each event carries what it names, because a build of
//! tightbeam without its `testing` feature keeps the label and drops the
//! value. The value repeats it in the form that the spec of a scenario
//! grades.
//!
//! The trail records decisions alone, never one event per update, so a
//! publish to many subscribers does not crowd the gate verdicts and the
//! handshakes out of a bounded trace.
//!
//! [`ServedMux::trace`]: tightbeam_ws::serve::ServedMux::trace

use tightbeam::urn;
use tightbeam::urn::Urn;

/// The registry admitted the connection. The label and the value are the
/// number of its [`ConnectionId`](crate::ConnectionId).
pub const CONNECTION_ADMITTED: Urn<'static> = urn!("tightbeam-pubsub", "event:connection/admitted");

/// The connection left the registry, because its serve ended or the delivery
/// policy expelled it. The label is the number of its
/// [`ConnectionId`](crate::ConnectionId), and the value is the count of
/// subscriptions it held.
pub const CONNECTION_LEFT: Urn<'static> = urn!("tightbeam-pubsub", "event:connection/left");

/// The delivery policy voted the connection off, ahead of its departure. The
/// name of the reason that it drains with, such as `enhance-your-calm`, is
/// both the label and the value.
pub const CONNECTION_EXPELLED: Urn<'static> = urn!("tightbeam-pubsub", "event:connection/expelled");

/// A wire command took no effect. The label names the command and the status
/// it answers, such as `sub PermissionDenied`, and the value is the status.
pub const COMMAND_REFUSED: Urn<'static> = urn!("tightbeam-pubsub", "event:command/refused");

/// A subscription dropped an update: the delivery policy dropped it from a
/// full queue, or the peer refused it, or the budget of the session could not
/// carry it. The label is the topic, and the value is the count of updates
/// that the subscription dropped so far.
pub const UPDATE_DROPPED: Urn<'static> = urn!("tightbeam-pubsub", "event:update/dropped");
