#![no_main]

use std::convert::TryFrom;

use libfuzzer_sys::fuzz_target;
use onc_rpc::*;

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);
    let msg = RpcMessage::try_from(bytes);
    if let Ok(m) = msg {
        // Assert round-tripping with Bytes and a byte slice produce identical
        // outputs.
        let slice_msg = RpcMessage::try_from(data).expect("failed to parse from bytes");
        let slice_buf = slice_msg.serialise().expect("should be able to serialise");

        let bytes_buf = m.serialise().expect("should be able to serialise");
        assert_eq!(slice_buf, bytes_buf, "equality");
    } else {
        // Equality between bytes and slice decoder.
        assert!(RpcMessage::try_from(data).is_err());
    }
});
