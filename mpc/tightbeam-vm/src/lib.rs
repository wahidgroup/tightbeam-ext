//! A bytecode VM for HoneyBadgerMPC programs over tightbeam.
//!
//! Consumers build a straight-line program against two typed register banks
//! (clear and secret), serialize it to DER, and submit it to every party over
//! the tightbeam control lane. Parties validate the bytes, agree on the
//! SHA3-256 digest, execute the program against the MPC engine, and deliver
//! result shares back to the consumer.
//!
//! # Pipeline
//!
//! ```text
//! ProgramBuilder -> Program -> DER bytes -> digest agreement
//!     -> ValidProgram -> Executor (engine ops + control-lane reveals)
//!     -> output shares -> consumer reconstruction
//! ```
//!
//! # Tracing
//!
//! Program bytes carry no tracing of their own. Hosts record lifecycle
//! events through injected [`TraceHandle`]s instead - the submission
//! verdict and round transitions via [`VmPartyConfig::trace`], the
//! submission flow via [`VmConsumer::with_trace`], and the
//! interpreter's execution events via the handle passed to
//! [`execute`] - so verification runs check live traces against
//! assertion specs and CSP process models.

pub mod backend;
pub mod builder;
pub mod codec;
pub mod consumer;
pub mod control;
pub mod error;
pub mod events;
pub mod executor;
pub mod isa;
pub mod party;
pub mod validate;

pub use backend::{HoneyBadgerBackend, SecretOps};
pub use builder::{Clear, ProgramBuilder, Secret};
pub use codec::ProgramDigest;
pub use consumer::VmConsumer;
pub use control::ControlMessage;
pub use error::{Bank, CodecError, Result, ValidationError, VmError};
pub use executor::{execute, Output};
pub use isa::{ClearRange, FixedPrecision, InputDecl, Instruction, MulTriple, Opcode, Program, SecretRange, VERSION};
pub use party::{VmParty, VmPartyConfig};
pub use tightbeam_mpc::{TraceEvent, TraceHandle};
pub use validate::{Budget, ValidProgram};
