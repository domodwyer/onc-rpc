#![no_main]

use std::convert::TryFrom;

use libfuzzer_sys::fuzz_target;
use onc_rpc::*;

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);
    let msg = RpcMessage::try_from(bytes);
    if let Ok(m) = msg {
        let mut buf = m.serialise().expect("should be able to serialise");
        assert_eq!(buf.as_slice(), data);

        // And check it matches the from_bytes data too
        let slice_msg = RpcMessage::from_bytes(data).expect("failed to parse from bytes");

        buf.clear();
        let mut c = std::io::Cursor::new(buf);
        slice_msg
            .serialise_into(&mut c)
            .expect("should be able to serialise");

        assert_eq!(c.into_inner().as_slice(), data);
    }
});
