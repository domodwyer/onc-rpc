# ONC RPC

This crate implements the `Open Network Computing Remote Procedure Call` system
(originally known as the Sun RPC system) as described in [RFC 1831] and [RFC
5531].

* Zero copy deserialisation
* Support for serialisation buffer reuse and pooling
* Only safe Rust code
* No heap allocations
* Simple, descriptive, one-to-one types matching the RFCs

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
parse_serialise -- -jobs=30` for parallised workers.

[deprecated]: https://tools.ietf.org/html/rfc2695#section-2
[RFC 1831]: https://tools.ietf.org/html/rfc1831
[RFC 5531]: https://tools.ietf.org/html/rfc5531
[`fuzz`]: https://github.com/domodwyer/onc-rpc/tree/master/fuzz
[`cargo fuzz`]: https://github.com/rust-fuzz/cargo-fuzz