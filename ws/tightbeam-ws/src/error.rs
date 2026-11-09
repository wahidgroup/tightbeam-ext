use tightbeam::Errorizable;

/// Result alias for fallible `tightbeam-ws` operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by the WebSocket transport.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::Error;
///
/// let error = Error::from(std::io::Error::other("refused"));
/// assert!(matches!(error, Error::Io(_)));
/// ```
#[derive(Debug, Errorizable)]
#[non_exhaustive]
pub enum Error {
	/// An underlying I/O operation failed.
	#[error("i/o error: {0}")]
	#[from]
	Io(std::io::Error),
	/// A tightbeam crypto, certificate, or transport operation failed.
	#[error("tightbeam error: {0}")]
	#[from]
	Tightbeam(tightbeam::TightBeamError),
	/// A transport-layer operation failed while driving a handshake.
	#[cfg(feature = "testing")]
	#[error("transport error: {0}")]
	#[from]
	Transport(tightbeam::transport::error::TransportError),
	/// A demo environment variable gave no value.
	#[cfg(feature = "testing")]
	#[error("environment error: {0}")]
	#[from]
	Env(crate::testing::EnvError),
	/// A gateway answered a hive registration with a status other than
	/// `Ok`.
	#[cfg(feature = "colony")]
	#[error("the gateway refused the hive registration with {0:?}")]
	Registration(tightbeam::policy::TransitStatus),
}

/// The tightbeam error of each failure, so a caller whose errors are
/// [`TightBeamError`](tightbeam::TightBeamError), such as the closures of a
/// tightbeam test scenario, takes these errors with `?`.
///
/// Each failure narrows to the tightbeam variant that names it. A missing
/// demo variable is `MissingConfiguration`, and a refused hive registration
/// is the `RegistrationFailed` cluster error. Neither tightbeam variant
/// carries the variable or the status, so a caller that needs either reads
/// this error before it converts.
impl From<Error> for tightbeam::TightBeamError {
	fn from(error: Error) -> Self {
		match error {
			Error::Io(io) => Self::IoError(io),
			Error::Tightbeam(error) => error,
			#[cfg(feature = "testing")]
			Error::Transport(error) => Self::TransportError(error),
			#[cfg(feature = "testing")]
			Error::Env(_) => Self::MissingConfiguration,
			#[cfg(feature = "colony")]
			Error::Registration(_) => {
				let refused = tightbeam::colony::cluster::ClusterError::RegistrationFailed;
				Self::ClusterError(Box::new(refused))
			}
		}
	}
}
