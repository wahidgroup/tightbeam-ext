//! The error of the test support, as `docs/ws.md` (Test support) states it.

use std::borrow::Cow;
use std::io;

use tightbeam::transport::error::TransportError;
use tightbeam::{Errorizable, TightBeamError};

use super::env::EnvError;
use super::fixtures::IdentityFilesError;

/// Result alias of the test support.
pub type Result<T> = core::result::Result<T, Error>;

/// The failures of the test support: a failure of the socket crate, the
/// refusals of the demo environment, the identity files, and the work plane,
/// and a count that an event watch waited out.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::testing::{EnvError, Error};
///
/// let error = Error::from(EnvError::Unset("TBWS_SERVER_CERT"));
/// assert_eq!(error.to_string(), "environment error: TBWS_SERVER_CERT is not set");
/// ```
#[derive(Debug, Errorizable)]
#[non_exhaustive]
pub enum Error {
	/// An I/O or tightbeam operation failed, as the socket crate reports it.
	#[error("{0}")]
	#[from]
	Ws(crate::Error),
	/// A transport-layer operation failed while driving a handshake.
	#[error("transport error: {0}")]
	#[from]
	Transport(TransportError),
	/// A demo environment variable gave no value.
	#[error("environment error: {0}")]
	#[from]
	Env(EnvError),
	/// The identity files refused a name, a certificate path, or a key file.
	#[error("identity files error: {0}")]
	#[from]
	IdentityFiles(IdentityFilesError),
	/// An event watch waited out its patience before its trace recorded the
	/// label as many times as the wait asked.
	#[error("the trace recorded {label} {recorded} times, short of {times}, within the patience of the event watch")]
	Unrecorded {
		/// The label that the wait watched.
		label: Cow<'static, str>,
		/// The count that the wait asked for.
		times: usize,
		/// The count that the trace reached.
		recorded: usize,
	},
	/// A gateway answered a hive registration with a status other than
	/// `Ok`.
	#[cfg(feature = "colony")]
	#[error("the gateway refused the hive registration with {0:?}")]
	Registration(tightbeam::policy::TransitStatus),
	/// A work gateway started with no edge plane.
	#[cfg(feature = "colony")]
	#[error("the gateway bound no edge plane")]
	EdgeUnbound,
}

/// A failed I/O operation of the test support is a failure of the socket crate.
impl From<io::Error> for Error {
	fn from(error: io::Error) -> Self {
		Self::Ws(crate::Error::Io(error))
	}
}

/// A failed tightbeam operation of the test support is a failure of the socket
/// crate.
impl From<TightBeamError> for Error {
	fn from(error: TightBeamError) -> Self {
		Self::Ws(crate::Error::Tightbeam(error))
	}
}

/// The tightbeam error of each failure, so a scenario closure takes these
/// errors with `?`.
///
/// - The conversion drops the name of a missing demo variable and the status of a refused registration.
/// - A refusal of the identity files becomes an I/O failure that holds the refusal as its inner error.
/// - A count that an event watch waited out becomes a timed-out I/O failure that holds the wait as its inner
///   error.
/// - [`io::Error::get_ref`] reads that inner error. The `source()` of an I/O failure answers the source of
///   its inner error, and skips the inner error itself (std 1.94.0 `io/error.rs:1072-1079`).
impl From<Error> for TightBeamError {
	fn from(error: Error) -> Self {
		match error {
			Error::Ws(error) => error.into(),
			Error::Transport(error) => Self::TransportError(error),
			Error::Env(_) => Self::MissingConfiguration,
			Error::IdentityFiles(refused) => Self::IoError(io::Error::new(io::ErrorKind::InvalidInput, refused)),
			unrecorded @ Error::Unrecorded { .. } => Self::IoError(io::Error::new(io::ErrorKind::TimedOut, unrecorded)),
			#[cfg(feature = "colony")]
			Error::Registration(_) => {
				let refused = tightbeam::colony::cluster::ClusterError::RegistrationFailed;
				Self::ClusterError(Box::new(refused))
			}
			#[cfg(feature = "colony")]
			Error::EdgeUnbound => Self::MissingConfiguration,
		}
	}
}
