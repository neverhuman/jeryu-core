//! Typed forge domain models.
//!
//! Split by resource into the submodules below; each `pub use x::*;` re-exports
//! its items so `crate::model::Thing` (and the crate-root `pub use
//! crate::model::*;`) resolves exactly as it did when this was a single
//! `model.rs`.

mod auth;
mod bots;
mod checks;
mod deployments;
mod issues;
mod jankurai;
mod policy;
mod pull_requests;
mod repo;
mod repository_transfer;
mod webhooks;

pub use auth::*;
pub use bots::*;
pub use checks::*;
pub use deployments::*;
pub use issues::*;
pub use jankurai::*;
pub use policy::*;
pub use pull_requests::*;
pub use repo::*;
pub use repository_transfer::*;
pub use webhooks::*;
