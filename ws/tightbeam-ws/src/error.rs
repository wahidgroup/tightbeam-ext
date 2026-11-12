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
}

/// The tightbeam error of each failure, so a caller whose errors are
/// [`TightBeamError`](tightbeam::TightBeamError), such as a scenario closure,
/// takes these errors with `?`.
impl From<Error> for tightbeam::TightBeamError {
	fn from(error: Error) -> Self {
		match error {
			Error::Io(io) => Self::IoError(io),
			Error::Tightbeam(error) => error,
		}
	}
}
