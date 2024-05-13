#![no_main]
use libfuzzer_sys::fuzz_target;
use onc_rpc::*;

fuzz_target!(|data: &[u8]| {
    let msg = RpcMessage::try_from(data);
    if let Ok(m) = msg {
        let buf = m.serialise().expect("should be able to serialise");
        assert_eq!(buf.as_slice(), data);
    }
});
