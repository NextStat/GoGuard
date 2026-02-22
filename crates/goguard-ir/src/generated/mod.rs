//! FlatBuffers-generated Rust code from `schemas/goguard-ir.fbs`.
//!
//! Regenerate with:
//! ```sh
//! flatc --rust -o crates/goguard-ir/src/generated/ schemas/goguard-ir.fbs
//! mv crates/goguard-ir/src/generated/goguard-ir_generated.rs \
//!    crates/goguard-ir/src/generated/goguard_ir_generated.rs
//! ```

// Suppress warnings on generated code.
#[allow(
    unused_imports,
    dead_code,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    deprecated,
    unused_qualifications
)]
mod goguard_ir_generated;

/// Re-export all generated FlatBuffers types from the `goguard.ir` namespace.
pub use goguard_ir_generated::goguard::ir::*;
