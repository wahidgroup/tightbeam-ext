//! What a coupled edge serves, and to whom: the routes from a gRPC method to
//! the servlet that serves it, and the grants of each method to principals.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tightbeam::crypto::x509::{Certificate, ErasedSigning, KeyPurposes, PeerCertificate};
use tightbeam::urn::Urn;

use super::principal::Principal;
use crate::edge::EdgeError;
use crate::protocol::{HEALTH_CHECK_PATH, TUNNEL_PATH};

/// How much a coupled call proves about its caller.
///
/// The variants are ordered, so a route that requires [`Assurance::Vouched`]
/// also admits a [`Assurance::Signed`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Assurance {
	/// The edge verified the TLS client chain of the caller, and the coupler
	/// vouches for the call under its own identity.
	Vouched,
	/// The caller also signed the call under its own tightbeam identity, over
	/// the method, the body, and its TLS certificate.
	Signed,
}

impl Assurance {
	/// The name that the audit trail records the assurance under.
	#[cfg(feature = "instrument")]
	pub(crate) const fn as_str(self) -> &'static str {
		match self {
			Self::Vouched => "vouched",
			Self::Signed => "signed",
		}
	}
}

/// The servlet that serves a routed method of a coupled edge, and the
/// certificate whose key signs its answers, which the coupler pins.
///
/// # Examples
///
/// ```no_run
/// use tightbeam::crypto::x509::Certificate;
/// use tightbeam::urn;
/// use tightbeam_grpc::couple::Servlet;
///
/// # fn servlet(place_signer: Certificate) -> Result<Servlet, tightbeam_grpc::edge::EdgeError> {
/// let place = Servlet::new(urn!("orders", "servlet:place"), place_signer)?;
/// # Ok(place)
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Servlet {
	urn: Urn<'static>,
	answered_by: Arc<PeerCertificate<ErasedSigning>>,
}

impl Servlet {
	/// The servlet type `urn`, whose answers the key of `answered_by` signs.
	///
	/// # Errors
	///
	/// - [`EdgeError::Trust`] -- `answered_by` is admitted for no signing.
	pub fn new(urn: Urn<'static>, answered_by: Certificate) -> Result<Self, EdgeError> {
		let answered_by = PeerCertificate::<ErasedSigning>::parse(answered_by, KeyPurposes::HOUSE.signer)?;
		Ok(Self { urn, answered_by: Arc::new(answered_by) })
	}

	/// The servlet type.
	pub(crate) fn urn(&self) -> &Urn<'static> {
		&self.urn
	}

	/// The certificate whose key signs the answers of the servlet.
	pub(crate) fn answered_by(&self) -> &PeerCertificate<ErasedSigning> {
		&self.answered_by
	}
}

/// One routed method: its target, and the assurance it requires.
#[derive(Clone, Debug)]
pub(crate) struct Route<T> {
	target: T,
	required: Assurance,
}

impl<T> Route<T> {
	/// What serves the method.
	pub(crate) fn target(&self) -> &T {
		&self.target
	}

	/// Whether the route admits a call of `presented` assurance.
	pub(crate) fn accepts(&self, presented: Assurance) -> bool {
		presented >= self.required
	}
}

/// The unary methods that a coupler or a backend routes, each to the target
/// `T` that serves it: a [`Servlet`] on a coupled edge, and `()` on a
/// [`Backend`](super::Backend), whose one channel serves every method.
///
/// A route is unary, because the edge of a gateway admits unary work alone.
///
/// # Examples
///
/// ```no_run
/// use tightbeam_grpc::couple::{Assurance, Routes, Servlet};
///
/// # fn routes(place: Servlet) -> Result<Routes<Servlet>, tightbeam_grpc::edge::EdgeError> {
/// let routes = Routes::new().unary("/orders.v1.Orders/Place", place, Assurance::Signed)?;
/// # Ok(routes)
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Routes<T> {
	table: HashMap<String, Route<T>>,
}

impl<T> Default for Routes<T> {
	fn default() -> Self {
		Self { table: HashMap::new() }
	}
}

impl<T> Routes<T> {
	/// No route, so nothing is served until a route is added.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Route the unary method `method`, such as `/orders.v1.Orders/Place`, to
	/// `target`, for calls of `required` assurance or more.
	///
	/// # Errors
	///
	/// - [`EdgeError::Method`] -- `method` is no path of the form
	///   `/package.Service/Method`, names the tunnel or the health service, or
	///   is routed already.
	pub fn unary(mut self, method: impl AsRef<str>, target: T, required: Assurance) -> Result<Self, EdgeError> {
		let method = method.as_ref();
		let reserved = method == TUNNEL_PATH || method == HEALTH_CHECK_PATH;
		if reserved || !is_method_path(method) || self.table.contains_key(method) {
			return Err(EdgeError::Method(method.to_owned()));
		}

		self.table.insert(method.to_owned(), Route { target, required });
		Ok(self)
	}

	/// The route of `method`, if it is routed.
	pub(crate) fn route(&self, method: &str) -> Option<&Route<T>> {
		self.table.get(method)
	}

	/// Refuse `grants` unless every method they name is routed, and refuse no
	/// route at all.
	///
	/// # Errors
	///
	/// - [`EdgeError::NoRoute`] -- no method is routed.
	/// - [`EdgeError::Method`] -- a grant names a method that no route serves.
	pub(crate) fn cover(&self, grants: &Grants) -> Result<(), EdgeError> {
		if self.table.is_empty() {
			return Err(EdgeError::NoRoute);
		}

		match grants.methods().find(|method| !self.table.contains_key(*method)) {
			Some(unrouted) => Err(EdgeError::Method(unrouted.to_owned())),
			None => Ok(()),
		}
	}
}

/// Whether `path` names one method of one service: `/`, a service name with
/// no `/`, `/`, and a method name with no `/`, all of visible ASCII.
fn is_method_path(path: &str) -> bool {
	let Some(rest) = path.strip_prefix('/') else {
		return false;
	};
	let Some((service, method)) = rest.split_once('/') else {
		return false;
	};

	let visible = path.bytes().all(|byte| byte.is_ascii_graphic());
	visible && !service.is_empty() && !method.is_empty() && !method.contains('/')
}

/// The methods that each principal may call. A coupled edge denies every
/// call that no grant names.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::couple::{Grants, Principal};
///
/// let grants = Grants::deny_all().grant(Principal::spiffe("spiffe://acme/billing")?, "/orders.v1.Orders/Place");
/// # Ok::<(), tightbeam_grpc::edge::EdgeError>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct Grants {
	table: HashMap<String, HashSet<Principal>>,
}

impl Grants {
	/// No grant, so every call is denied.
	#[must_use]
	pub fn deny_all() -> Self {
		Self::default()
	}

	/// Grant `principal` the method `method`. `Coupler::new` refuses a grant
	/// of a method that no route serves.
	#[must_use]
	pub fn grant(mut self, principal: Principal, method: impl Into<String>) -> Self {
		self.table.entry(method.into()).or_default().insert(principal);
		self
	}

	/// Whether `principal` may call `method`.
	pub(crate) fn permits(&self, principal: &Principal, method: &str) -> bool {
		self.table.get(method).is_some_and(|principals| principals.contains(principal))
	}

	/// Every method that a grant names.
	pub(crate) fn methods(&self) -> impl Iterator<Item = &str> {
		self.table.keys().map(String::as_str)
	}
}
