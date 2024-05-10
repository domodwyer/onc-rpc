#![doc = include_str!("../README.md")]
#![deny(rustdoc::broken_intra_doc_links, rust_2018_idioms)]
#![warn(
    clippy::clone_on_ref_ptr,
    clippy::dbg_macro,
    clippy::explicit_iter_loop,
    clippy::future_not_send,
    clippy::todo,
    clippy::unimplemented,
    clippy::use_self,
    clippy::doc_markdown,
    clippy::print_stdout,
    missing_debug_implementations,
    unused_crate_dependencies,
    unreachable_pub,
    missing_docs
)]

mod errors;
pub use errors::Error;

mod rpc_message;
pub use rpc_message::*;

mod call_body;
pub use call_body::*;

mod reply;
pub use reply::*;

pub mod auth;

mod bytes_ext;

// Unused crate lint workaround for dev dependency.
#[cfg(test)]
use criterion as _;
