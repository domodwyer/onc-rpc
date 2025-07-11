#![no_main]
use libfuzzer_sys::fuzz_target;
use onc_rpc::*;

fuzz_target!(|data: &[u8]| {
    let got = RpcMessage::try_from(data);
    if let Ok(m) = got {
        let buf = m.serialise().expect("should be able to serialise");
        let got2 = RpcMessage::try_from(buf.as_slice()).expect("must be valid");
        assert_eq!(m, got2);
    }
});
