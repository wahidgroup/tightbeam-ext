//! The coupler: stock gRPC callers on the edge of a tightbeam colony.
//!
//! A coupled edge serves two kinds of call on one TLS port. A native
//! tightbeam client opens the tunnel, and a stock gRPC client calls a routed
//! unary method. The coupler carries each stock call as work of the colony:
//!
//! 1. The edge verifies the TLS client chain of the caller under
//!    [`CallerTrust`], and the chain names one [`Principal`].
//! 2. The call proves [`Assurance::Vouched`], or [`Assurance::Signed`] when
//!    it carries a [`CallClaim`] that its caller signed with a
//!    [`ClaimSigner`].
//! 3. [`Grants`] permit the principal the method, and the [`Routes`] entry of
//!    the method accepts the assurance.
//! 4. The [`Voucher`] signs the call as a [`CoupledCall`] and submits it
//!    through one loopback session into the accept queue of the listener, so
//!    the gateway admits it as it admits the work of a native client.
//! 5. The servlet admits the call through [`AdmittedCall::admit`] under its
//!    [`AdmissionTrust`], and answers a signed [`CoupledReply`], whose
//!    signature the coupler verifies under the signer of the route before it
//!    answers the caller.
//!
//! In the other direction, a [`Backend`] servlet relays the coupled calls it
//! admits to a stock gRPC server through a [`BackendChannel`], under the TLS
//! identity of the adapter, with the principal of each call in its metadata.
//!
//! # Sources
//!
//! - gRPC over HTTP2, `grpc/grpc` `doc/PROTOCOL-HTTP2.md`: <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>
//! - CWE-863, Incorrect Authorization: <https://cwe.mitre.org/data/definitions/863.html>

mod admit;
mod backend;
mod claim;
mod fault;
mod loopback;
mod message;
mod principal;
mod routes;
mod saga;
mod trust;
mod voucher;

pub use admit::{AdmissionTrust, AdmittedCall};
pub use backend::{Backend, BackendChannel};
pub use claim::{CallClaim, ClaimSigner};
pub use message::{CoupledCall, CoupledReply};
pub use principal::Principal;
pub use routes::{Assurance, Grants, Routes, Servlet};
pub use saga::Coupler;
pub use tonic::Code;
pub use trust::CallerTrust;
pub use voucher::Voucher;

pub(crate) use fault::CallFault;
pub(crate) use principal::Caller;
pub(crate) use saga::{LiveCoupler, Opened};
