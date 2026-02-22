//! GoGuard diagnostics — diagnostic types, formatting, and output.

pub mod agent;
pub mod diagnostic;
pub mod executable;
pub mod fix_generator;
pub mod full;
pub mod human;
pub mod markdown;
pub mod rules;
pub mod sarif;
pub mod skeleton;

pub use diagnostic::*;
