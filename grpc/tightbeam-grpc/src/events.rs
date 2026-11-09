//! The events that a listener records on its audit trail, under the
//! `instrument` feature.
//!
//! A listener records the calls that it refuses before any tightbeam session
//! exists, on the trace that [`GrpcListener::with_trace`] attaches, or on the
//! trace of its coupler for a coupled edge. A session that a tunnel opens
//! records on the trace of its own transport, as every tightbeam session does.
//! Under the `couple` feature, a coupler records each call it admits, refuses,
//! and answers.
//!
//! [`GrpcListener::with_trace`]: crate::protocol::GrpcListener::with_trace

use tightbeam::urn;
use tightbeam::urn::Urn;

/// A call that the listener refused before any session existed. The name of
/// the refusal is both its label and its value: `method`, `media-type`,
/// `path`, `busy`, or `unconnected`.
///
/// tonic refuses an encoding other than identity inside the call that the
/// tunnel admitted, with no refusal of the tunnel, so that refusal records
/// nothing here.
pub const TUNNEL_REFUSED: Urn<'static> = urn!("tightbeam-grpc", "event:tunnel/refused");

/// A coupled call that the coupler admitted, before it vouches for it: the
/// method as its label, and the assurance the call proves, `vouched` or
/// `signed`, as its value.
#[cfg(feature = "couple")]
pub const COUPLED_CALL_ADMITTED: Urn<'static> = urn!("tightbeam-grpc", "event:coupled/admitted");

/// A coupled call that the coupler refused: the name of the refusal as its
/// label and its value, such as `unauthenticated`, `denied`, or `replayed`.
#[cfg(feature = "couple")]
pub const COUPLED_CALL_REFUSED: Urn<'static> = urn!("tightbeam-grpc", "event:coupled/refused");

/// A coupled call whose verified answer the coupler relayed: the method as its
/// label, and the gRPC status code of the answer as its value.
#[cfg(feature = "couple")]
pub const COUPLED_CALL_ANSWERED: Urn<'static> = urn!("tightbeam-grpc", "event:coupled/answered");

/// A call that a backend adapter relayed to its stock gRPC server: the method
/// as its label, and the gRPC status code of the answer of the server as its
/// value.
#[cfg(feature = "couple")]
pub const BACKEND_CALL_RELAYED: Urn<'static> = urn!("tightbeam-grpc", "event:backend/relayed");

/// A call that a backend adapter refused before it called its server: the
/// name of the refusal, `unrouted` or `denied`, as its label and its value.
#[cfg(feature = "couple")]
pub const BACKEND_CALL_REFUSED: Urn<'static> = urn!("tightbeam-grpc", "event:backend/refused");
