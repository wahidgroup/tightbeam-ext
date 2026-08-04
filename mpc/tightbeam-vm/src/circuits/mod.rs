//! Composed bit-circuit helpers built only from the public ISA surface.
//!
//! These modules expand into ordinary [`crate::Instruction`] streams.
//! They are not mega-opcodes: consumers call them through
//! [`crate::ProgramBuilder`] the same way they call `mul` or `eq`.

pub mod aes128;
