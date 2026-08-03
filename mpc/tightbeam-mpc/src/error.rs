//! Typed failures for the MPC network adapter.
//!
//! Everything inside the crate speaks [`Error`]; the [`stoffelnet`]
//! trait boundary flattens it into [`NetworkError`] through the
//! [`From`] impl at the bottom, so protocol code sees the small error
//! space it already handles while operators keep the full cause chain.

use core::fmt;
use std::error::Error as StdError;

use stoffelnet::network_utils::{ClientId, NetworkError, PartyId};
use tightbeam::TightBeamError;

/// Why a [`Roster`](crate::Roster) refused to assemble.
#[derive(Debug)]
pub enum RosterError {
	/// A roster needs at least one party.
	Empty,
	/// Party ids must be dense `0..n` so they double as share indices.
	NonContiguousIds {
		/// The id the dense ordering required at this position.
		expected: PartyId,
		/// The id actually found.
		found: PartyId,
	},
	/// The local identity names a party the roster does not contain.
	LocalPartyMissing {
		/// The missing party id.
		id: PartyId,
	},
	/// The local identity certificate differs from the roster entry.
	CertificateMismatch {
		/// The party whose roster certificate disagrees.
		id: PartyId,
	},
	/// A client id collides with a party id or another client.
	ClientIdTaken {
		/// The colliding client id.
		id: ClientId,
	},
	/// A client certificate duplicates a party or client certificate,
	/// which would make link attribution ambiguous.
	AmbiguousCertificate {
		/// The client presenting the duplicate certificate.
		id: ClientId,
	},
	/// The local identity names a client the roster does not authorize.
	UnknownClient {
		/// The unauthorized client id.
		id: ClientId,
	},
}

impl fmt::Display for RosterError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Empty => f.write_str("the roster is empty"),
			Self::NonContiguousIds { expected, found } => {
				write!(f, "party ids must be dense: expected {expected}, found {found}")
			}
			Self::LocalPartyMissing { id } => {
				write!(f, "the local party {id} is not in the roster")
			}
			Self::CertificateMismatch { id } => {
				write!(f, "the local certificate does not match the roster entry for party {id}")
			}
			Self::ClientIdTaken { id } => {
				write!(f, "client id {id} collides with a party or another client")
			}
			Self::AmbiguousCertificate { id } => {
				write!(f, "the certificate for client {id} duplicates another roster certificate")
			}
			Self::UnknownClient { id } => {
				write!(f, "client {id} is not authorized by the roster")
			}
		}
	}
}

impl StdError for RosterError {}

/// Why an adapter operation failed.
#[derive(Debug)]
pub enum Error {
	/// The roster refused to assemble.
	Roster(RosterError),
	/// A tightbeam operation (transport, handshake, frame codec) failed.
	Beam(TightBeamError),
	/// The peer never completed the ECIES handshake.
	HandshakeIncomplete {
		/// The party the link was for, when the dialer knows it.
		peer: Option<PartyId>,
	},
	/// The handshake completed without negotiating multiplexing.
	MuxNotNegotiated {
		/// The party the link was for, when the dialer knows it.
		peer: Option<PartyId>,
	},
	/// An accepted connection authenticated with a certificate outside
	/// the roster, or presented none.
	UnknownPeerCertificate,
	/// A roster member dialed against the deterministic dial rule.
	UnexpectedDialer {
		/// The party that dialed.
		peer: PartyId,
	},
	/// The mesh missed peers within the establishment deadline.
	MeshIncomplete {
		/// Links established so far.
		connected: usize,
		/// Links the full mesh needs.
		expected: usize,
	},
	/// No live link to the party and re-dialing did not restore one.
	LinkUnavailable {
		/// The unreachable party.
		peer: PartyId,
	},
	/// The party id is outside the roster.
	PartyNotFound {
		/// The unknown party id.
		peer: PartyId,
	},
	/// No live link to the client: it never connected, or its link died
	/// and only the client can restore it by dialing back in.
	ClientNotConnected {
		/// The unreachable client.
		client: ClientId,
	},
	/// Not every expected consumer held a live link before the deadline.
	ClientsNotReady {
		/// How many of the expected clients were connected.
		connected: usize,
		/// How many clients the caller required.
		expected: usize,
	},
	/// The inbox receiver was dropped; delivered messages have nowhere
	/// to go.
	InboxClosed,
	/// A frame carried a lane discriminant this build does not know.
	UnknownLane {
		/// The unrecognized lane octet.
		lane: u8,
	},
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Roster(cause) => write!(f, "the roster refused to assemble: {cause}"),
			Self::Beam(cause) => write!(f, "the tightbeam operation failed: {cause}"),
			Self::HandshakeIncomplete { peer: Some(peer) } => {
				write!(f, "the handshake with party {peer} never completed")
			}
			Self::HandshakeIncomplete { peer: None } => {
				f.write_str("the handshake with an accepted connection never completed")
			}
			Self::MuxNotNegotiated { peer: Some(peer) } => {
				write!(f, "the link to party {peer} did not negotiate multiplexing")
			}
			Self::MuxNotNegotiated { peer: None } => f.write_str("an accepted link did not negotiate multiplexing"),
			Self::UnknownPeerCertificate => f.write_str("the peer certificate does not belong to any roster party"),
			Self::UnexpectedDialer { peer } => {
				write!(f, "party {peer} dialed against the dial rule")
			}
			Self::MeshIncomplete { connected, expected } => {
				write!(f, "the mesh established {connected} of {expected} links before the deadline")
			}
			Self::LinkUnavailable { peer } => {
				write!(f, "no live link to party {peer}")
			}
			Self::PartyNotFound { peer } => {
				write!(f, "party {peer} is not in the roster")
			}
			Self::ClientNotConnected { client } => {
				write!(f, "no live link to client {client}")
			}
			Self::ClientsNotReady { connected, expected } => {
				write!(f, "only {connected} of {expected} clients connected before the deadline")
			}
			Self::InboxClosed => f.write_str("the inbox receiver is gone"),
			Self::UnknownLane { lane } => {
				write!(f, "unknown frame lane {lane}")
			}
		}
	}
}

impl StdError for Error {
	fn source(&self) -> Option<&(dyn StdError + 'static)> {
		match self {
			Self::Roster(cause) => Some(cause),
			Self::Beam(cause) => Some(cause),
			_ => None,
		}
	}
}

impl From<RosterError> for Error {
	fn from(cause: RosterError) -> Self {
		Self::Roster(cause)
	}
}

impl From<TightBeamError> for Error {
	fn from(cause: TightBeamError) -> Self {
		Self::Beam(cause)
	}
}

/// Flatten the adapter error space into the one the MPC engine handles.
///
/// Identity and delivery failures collapse to [`NetworkError::SendError`]
/// because that is the retryable class HoneyBadger already tolerates;
/// only addressing errors keep their id so the protocol can name the
/// missing party.
impl From<Error> for NetworkError {
	fn from(cause: Error) -> Self {
		match cause {
			Error::PartyNotFound { peer } => NetworkError::PartyNotFound(peer),
			Error::ClientNotConnected { client } => NetworkError::ClientNotFound(client),
			Error::MeshIncomplete { .. } | Error::ClientsNotReady { .. } => NetworkError::Timeout,
			_ => NetworkError::SendError,
		}
	}
}

/// Crate-wide result alias.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
	use super::*;

	fn displays_of(errors: &[Error]) -> Vec<String> {
		errors.iter().map(|error| error.to_string()).collect()
	}

	#[test]
	fn every_variant_displays_context() {
		let errors = [
			Error::Roster(RosterError::Empty),
			Error::HandshakeIncomplete { peer: Some(3) },
			Error::HandshakeIncomplete { peer: None },
			Error::MuxNotNegotiated { peer: Some(2) },
			Error::MuxNotNegotiated { peer: None },
			Error::UnknownPeerCertificate,
			Error::UnexpectedDialer { peer: 4 },
			Error::MeshIncomplete { connected: 1, expected: 4 },
			Error::LinkUnavailable { peer: 1 },
			Error::PartyNotFound { peer: 9 },
			Error::ClientNotConnected { client: 100 },
			Error::ClientsNotReady { connected: 0, expected: 1 },
			Error::InboxClosed,
			Error::UnknownLane { lane: 9 },
		];

		let all_named = displays_of(&errors).iter().all(|text| !text.is_empty());
		assert!(all_named);
	}

	#[test]
	fn roster_cause_is_chained() {
		let error = Error::from(RosterError::NonContiguousIds { expected: 1, found: 3 });
		assert!(error.source().is_some());
	}

	#[test]
	fn addressing_errors_keep_the_party_id() {
		let mapped = NetworkError::from(Error::PartyNotFound { peer: 7 });
		assert_eq!(mapped, NetworkError::PartyNotFound(7));
	}

	#[test]
	fn mesh_deadline_maps_to_timeout() {
		let mapped = NetworkError::from(Error::MeshIncomplete { connected: 0, expected: 2 });
		assert_eq!(mapped, NetworkError::Timeout);
	}

	#[test]
	fn delivery_failures_collapse_to_send_error() {
		let mapped = NetworkError::from(Error::LinkUnavailable { peer: 2 });
		assert_eq!(mapped, NetworkError::SendError);
	}

	#[test]
	fn missing_clients_keep_the_client_id() {
		let mapped = NetworkError::from(Error::ClientNotConnected { client: 100 });
		assert_eq!(mapped, NetworkError::ClientNotFound(100));
	}

	#[test]
	fn client_readiness_deadline_maps_to_timeout() {
		let mapped = NetworkError::from(Error::ClientsNotReady { connected: 0, expected: 2 });
		assert_eq!(mapped, NetworkError::Timeout);
	}
}
