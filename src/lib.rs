//! An implementation of RFC 5531, including the defined types, authentication
//! flavors and fast (de)serialisation.

#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    clippy::doc_markdown,
    clippy::print_stdout,
    clippy::todo,
    clippy::unimplemented
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

// TODO: code examples
