//! The events that an edge or a backend adapter records on its audit trail,
//! under the `instrument` feature. `docs/grpc.md` lists who records each one.

use tightbeam::urn;
use tightbeam::urn::Urn;

/// A call or a connection that the edge refused before any session existed.
/// The name of the refusal is both its label and its value:
///
/// - A call: `method`, `media-type`, `path`, `unconnected`, or `queue-full`.
/// - A tunnel call that the lane of its connection refused: `no-slot`,
///   `other-kind`, `tunnel-held`, or `closed`.
/// - A connection: `tls` for a TLS handshake that failed, `late` for one that
///   passed neither its PROXY header nor its handshake in time, and `no-timer`
///   for one whose wait the clock of the edge gave no timer.
pub const EDGE_REFUSED: Urn<'static> = urn!("tightbeam-grpc", "event:edge/refused");

/// A PROXY protocol v2 header that a hop sent ahead of a connection, which
/// the edge read. The label is `client` for a header that names the client
/// of the connection, or `local` for one that keeps the hop as the peer, such
/// as a health check of the hop. The value is the peer that the edge takes.
pub const PROXY_HEADER_READ: Urn<'static> = urn!("tightbeam-grpc", "event:proxy/read");

/// A connection of a hop whose PROXY header the edge refused, which then
/// closes: `malformed` for no header or a malformed one, and `ended` for a
/// connection that ends within its header. The name is both its label and its
/// value.
pub const PROXY_HEADER_REFUSED: Urn<'static> = urn!("tightbeam-grpc", "event:proxy/refused");

/// A loopback session of a coupler that opened, once it read the deadline of
/// its first probe: `opened` as its label and its value.
#[cfg(feature = "couple")]
pub const COUPLED_SESSION_OPENED: Urn<'static> = urn!("tightbeam-grpc", "event:coupled/session-opened");

/// A coupled call that its head opened on its lane, under the deadline that
/// the head read, before its body: the method as its label and its value.
#[cfg(feature = "couple")]
pub const COUPLED_CALL_OPENED: Urn<'static> = urn!("tightbeam-grpc", "event:coupled/opened");

/// A coupled call that the coupler admitted, before it vouches for it: the
/// method as its label, and the assurance the call proves, `bearer`,
/// `vouched`, or `signed`, as its value.
#[cfg(feature = "couple")]
pub const COUPLED_CALL_ADMITTED: Urn<'static> = urn!("tightbeam-grpc", "event:coupled/admitted");

/// A coupled call that the coupler refused: the name of the refusal as its
/// label and its value, such as `unauthenticated`, `denied`, or `replayed`.
/// A call that the lane of its connection refused reads the name of the lane
/// refusal: `no-permit`, `calls-exhausted`, `other-kind`, or `closed`.
#[cfg(feature = "couple")]
pub const COUPLED_CALL_REFUSED: Urn<'static> = urn!("tightbeam-grpc", "event:coupled/refused");

/// A coupled call whose verified answer the coupler relayed: the method as its
/// label, and the gRPC status code of the answer as its value.
#[cfg(feature = "couple")]
pub const COUPLED_CALL_ANSWERED: Urn<'static> = urn!("tightbeam-grpc", "event:coupled/answered");

/// A claim that the ledger of the coupler took for a signed call, before the
/// call sends: `spent` as its label and its value.
#[cfg(feature = "couple")]
pub const COUPLED_CLAIM_SPENT: Urn<'static> = urn!("tightbeam-grpc", "event:coupled/claim-spent");

/// A spent claim that the coupler forgot, so its caller may present it again.
/// The cause is its label and its value:
///
/// - `unsent` for a send whose frame stayed in the loopback session.
/// - `deadline` for a ledger that answered past the deadline of the call.
/// - `no-timer` for a ledger whose wait the clock gave no timer.
#[cfg(feature = "couple")]
pub const COUPLED_CLAIM_FORGOTTEN: Urn<'static> = urn!("tightbeam-grpc", "event:coupled/claim-forgotten");

/// A call that a backend adapter relayed to its stock gRPC server: the method
/// as its label, and the gRPC status code of the answer of the server as its
/// value.
#[cfg(feature = "couple")]
pub const BACKEND_CALL_RELAYED: Urn<'static> = urn!("tightbeam-grpc", "event:backend/relayed");

/// A call that a backend adapter refused: the name of the refusal, `unrouted`
/// or `denied` before it called its server, or `part` for a part of a stream
/// that ended the call, as its label and its value.
#[cfg(feature = "couple")]
pub const BACKEND_CALL_REFUSED: Urn<'static> = urn!("tightbeam-grpc", "event:backend/refused");
