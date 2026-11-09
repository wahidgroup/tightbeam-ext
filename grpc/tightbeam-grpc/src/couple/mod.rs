//! The coupler: stock gRPC callers on the edge of a colony, and colony work
//! out to stock gRPC servers. `docs/grpc.md` describes both directions.

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
