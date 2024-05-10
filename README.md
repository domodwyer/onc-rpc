[![crates.io](https://img.shields.io/crates/v/onc-rpc.svg)](https://crates.io/crates/onc-rpc)
[![docs.rs](https://docs.rs/onc-rpc/badge.svg)](https://docs.rs/onc-rpc)

# ONC RPC

This crate implements the `Open Network Computing Remote Procedure Call` system
(originally known as the Sun RPC system) as described in [RFC 1831] and [RFC
5531].

* Zero copy deserialisation
* Support for serialisation buffer reuse and pooling
* Only safe Rust code
* No heap allocations
* Simple, descriptive, one-to-one types matching the RFCs

## Example

```rust
use onc_rpc::{
    auth::{AuthFlavor, AuthUnixParams},
    CallBody,
    MessageType,
    RpcMessage,
};

// Add RPC call authentication.
let auth_params = AuthUnixParams::new(42, "bananas.local", 501, 501, None);

// Build a dummy byte payload.
let payload = vec![42, 42, 42, 42];

// Construct the actual RPC message.
let msg = RpcMessage::new(
    4242,
    MessageType::Call(CallBody::new(
        100000, 							// Program number
        42,									// Program version
        13,									// Procedure number
        AuthFlavor::AuthUnix(auth_params),	// Credentials
        AuthFlavor::AuthNone(None),			// Response verifier
        &payload,
    )),
);

// Serialise the RPC message into anything that implements std::io::Write
let mut network_buffer = Vec::new();
msg.serialise_into(&mut network_buffer).expect("serialise message");

// And do something with it!
```

## Limitations

I had no use for the following, however PRs to extend this crate are happily
accepted :)

* No support for fragmented messages
* No support for the [deprecated] and trivially broken Diffie-Hellman
  authentication flavor
* No defined GSS / Kerberos auth flavor types

The auth flavors not included in this crate can still be used as the flavor
discriminant and associated opaque data is available in the application layer -
this crate just lacks pre-defined types to describe them.

## Future development

Currently a buffer has to be passed to serialise the complete message into a
continuous memory region - it would be nicer to support vectorised I/O to
provide zero-copy serialisation too.

## Fuzzing
Included in the `fuzz/` directory is a deserialisation fuzzer that attempts to
decode arbitrary inputs, and if successful serialises the resulting message and
compares the result with the input.

Install [`cargo fuzz`] and invoke the fuzzer with `cargo fuzz run
parse_serialise -- -jobs=30` for parallelised workers.

[deprecated]: https://tools.ietf.org/html/rfc2695#section-2
[RFC 1831]: https://tools.ietf.org/html/rfc1831
[RFC 5531]: https://tools.ietf.org/html/rfc5531
[`fuzz`]: https://github.com/domodwyer/onc-rpc/tree/master/fuzz
[`cargo fuzz`]: https://github.com/rust-fuzz/cargo-fuzz
