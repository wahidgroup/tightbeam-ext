//! The patience that the scenarios of this crate share.

use core::time::Duration;

/// How long a wait on a peer may take before the scenario fails instead of
/// hanging.
pub const DEADLINE: Duration = Duration::from_secs(5);
