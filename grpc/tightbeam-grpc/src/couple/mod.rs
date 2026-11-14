//! The coupler: stock gRPC callers on the edge of a colony, and colony work
//! out to stock gRPC servers. `docs/grpc.md` describes both directions.

mod admit;
mod backend;
mod bearer;
mod claim;
mod error;
mod fault;
mod forwarded;
mod ledger;
mod limits;
mod loopback;
mod message;
mod metadata;
mod method;
mod principal;
mod proof;
mod reflection;
mod routes;
mod saga;
mod serve;
mod stream;
mod trust;
mod voucher;
mod web;

#[cfg(feature = "testing")]
pub(crate) mod parts;

pub use admit::{AdmissionTrust, AdmittedCall, Origin};
pub use backend::{Backend, BackendChannel};
pub use bearer::BearerTrust;
pub use claim::{CallClaim, ClaimSigner};
pub use error::CoupleError;
pub use ledger::{ClaimKey, ClaimLedger, ClaimSpend, HolderId, LedgerError, LedgerFuture, MemoryLedger, SignerDigest};
pub use limits::CallLimits;
pub use message::{CoupledCall, CoupledReply};
pub use metadata::Metadata;
pub use method::MethodPath;
pub use principal::Principal;
pub use routes::{Assurance, Grants, Routes, Servlet};
pub use saga::Coupler;
pub use stream::{AdmittedStream, AdmittedStreamParts, StreamAnswers, StreamRefusal, StreamRequests};
pub use tonic::Code;
pub use trust::{CallerTrust, CallerTrustFiles};
pub use voucher::{Identities, Voucher};

pub(crate) use fault::CallFault;
pub(crate) use principal::TlsIdentity;
pub(crate) use routes::AccessRefusal;
pub(crate) use saga::{CallRecorder, LiveCoupler, PreparedCoupler};
pub(crate) use trust::{Credential, LiveCallers};
pub(crate) use web::WebCall;
