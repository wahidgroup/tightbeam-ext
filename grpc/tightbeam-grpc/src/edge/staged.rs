//! The material of a profile that a deployment stages at run time.

use std::sync::{Mutex, PoisonError};

use super::{Dial, Edge, EdgeError};

/// The material of a staged profile.
struct Staged {
	edge: Edge,
	dial: Dial,
}

/// The cell of a profile that [`staged_profile!`](crate::staged_profile)
/// declares: the material that a deployment stages at run time, which every
/// later bind and dial of the profile reads.
pub struct StagedCell {
	staged: Mutex<Option<Staged>>,
}

impl StagedCell {
	/// An empty cell, so a bind or a dial before the stage fails with
	/// [`EdgeError::Unprovisioned`].
	#[must_use]
	pub const fn new() -> Self {
		Self { staged: Mutex::new(None) }
	}

	/// Stage `edge` for every later bind and `dial` for every later dial, in
	/// place of the material of an earlier stage.
	pub fn stage(&self, edge: Edge, dial: Dial) {
		let mut staged = self.staged.lock().unwrap_or_else(PoisonError::into_inner);
		*staged = Some(Staged { edge, dial });
	}

	/// The staged setup of a bind.
	///
	/// # Errors
	///
	/// - [`EdgeError::Unprovisioned`] -- nothing is staged.
	pub fn edge(&self) -> Result<Edge, EdgeError> {
		let staged = self.staged.lock().unwrap_or_else(PoisonError::into_inner);
		let edge = staged.as_ref().map(|staged| staged.edge.clone());
		edge.ok_or(EdgeError::Unprovisioned)
	}

	/// The staged setup of a dial.
	///
	/// # Errors
	///
	/// - [`EdgeError::Unprovisioned`] -- nothing is staged.
	pub fn dial(&self) -> Result<Dial, EdgeError> {
		let staged = self.staged.lock().unwrap_or_else(PoisonError::into_inner);
		let dial = staged.as_ref().map(|staged| staged.dial.clone());
		dial.ok_or(EdgeError::Unprovisioned)
	}
}

impl Default for StagedCell {
	fn default() -> Self {
		Self::new()
	}
}

/// Declares an [`EdgeProfile`](crate::edge::EdgeProfile) whose material a
/// deployment stages at run time, through `stage(edge, dial)`, before its
/// gateway binds. `docs/grpc.md` gives the rules of its static cell.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::edge::{Dial, Edge, EdgeProfile};
///
/// tightbeam_grpc::staged_profile! {
/// 	/// The edge of one deployment.
/// 	OrdersEdge
/// }
///
/// assert!(OrdersEdge::edge().is_err());
///
/// OrdersEdge::stage(Edge::h2c(), Dial::H2c);
/// assert!(OrdersEdge::edge().is_ok());
/// ```
#[macro_export]
macro_rules! staged_profile {
	($(#[$meta:meta])* $vis:vis $name:ident) => {
		$(#[$meta])*
		$vis struct $name;

		impl $name {
			fn cell() -> &'static $crate::edge::StagedCell {
				static CELL: $crate::edge::StagedCell = $crate::edge::StagedCell::new();
				&CELL
			}

			/// Stage `edge` for every later bind and `dial` for every later
			/// dial of this profile.
			$vis fn stage(edge: $crate::edge::Edge, dial: $crate::edge::Dial) {
				Self::cell().stage(edge, dial);
			}
		}

		impl $crate::edge::EdgeProfile for $name {
			fn edge() -> ::core::result::Result<$crate::edge::Edge, $crate::edge::EdgeError> {
				Self::cell().edge()
			}

			fn dial() -> ::core::result::Result<$crate::edge::Dial, $crate::edge::EdgeError> {
				Self::cell().dial()
			}
		}
	};
}
