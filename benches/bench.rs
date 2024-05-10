use std::{
    convert::{TryFrom, TryInto},
    io::Cursor,
};

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use onc_rpc::{
    auth::{AuthFlavor, AuthUnixParams},
    CallBody, MessageType, RpcMessage,
};
use smallvec::smallvec;

pub fn auth(c: &mut Criterion) {
    c.bench_function("deserialise_auth_unix", |b| {
        let raw = hex!(
            "00000001000000540000000000000000000001f50000001400000010000001f500
			00000c000000140000003d0000004f000000500000005100000062000002bd00000
			02100000064000000cc000000fa0000018b0000018e0000018f"
        );
        let raw_ref: &[u8] = raw.as_ref();

        b.iter(|| {
            let a: AuthFlavor<&[u8]> = raw_ref.try_into().unwrap();
            black_box(a)
        })
    });

    c.bench_function("auth_unix_gids_read", |b| {
        let gids =
            smallvec![501, 12, 20, 61, 79, 80, 81, 98, 701, 33, 100, 204, 250, 395, 398, 399,];
        let p = AuthUnixParams::new(0, "", 501, 20, Some(gids));

        b.iter(|| black_box(p.gids()))
    });

    c.bench_function("deserialise_auth_none_with_data", |b| {
        let raw = hex!(
            "00000000000000540000000000000000000001f50000001400000010000001f500
			00000c000000140000003d0000004f000000500000005100000062000002bd00000
			02100000064000000cc000000fa0000018b0000018e0000018f"
        );
        let raw_ref: &[u8] = raw.as_ref();

        b.iter(|| {
            let a: AuthFlavor<&[u8]> = raw_ref.try_into().unwrap();
            black_box(a)
        })
    });
}

pub fn rpc_message(c: &mut Criterion) {
    c.bench_function("deserialise_rpc_message", |b| {
        let raw = hex!(
            "80000098265ec1060000000000000002000186a300000004000000010000000100
    		0000180000000000000000000000000000000000000001000000000000000000000
    		0000000000c6163636573732020202020200000000000000003000000160000001f
    		4300004d1a436f6c452240ea4c70a1b52d7f97418e6601a10e02009cf2d59c00000
    		000030000003f00000009000000021010011a00b0a23a"
        );
        let raw_ref: &[u8] = raw.as_ref();

        b.iter(|| {
            let a = RpcMessage::from_bytes(raw_ref).unwrap();
            black_box(a)
        })
    });

    c.bench_function("deserialise_rpc_message_from_bytes", |b| {
        let raw: [u8; 156] = hex!(
            "80000098265ec1060000000000000002000186a300000004000000010000000100
    		0000180000000000000000000000000000000000000001000000000000000000000
    		0000000000c6163636573732020202020200000000000000003000000160000001f
    		4300004d1a436f6c452240ea4c70a1b52d7f97418e6601a10e02009cf2d59c00000
    		000030000003f00000009000000021010011a00b0a23a"
        );
        let bytes = Bytes::copy_from_slice(raw.as_ref());

        b.iter(|| {
            let a = RpcMessage::try_from(bytes.clone()).unwrap();
            black_box(a)
        })
    });

    c.bench_function("serialise_into_rpc_message_no_payload", |b| {
        let gids =
            smallvec![501, 12, 20, 61, 79, 80, 81, 98, 701, 33, 100, 204, 250, 395, 398, 399,];
        let params = AuthUnixParams::new(0, "", 501, 20, Some(gids));
        let payload = vec![];
        let msg = RpcMessage::new(
            4242,
            MessageType::Call(CallBody::new(
                100000,
                42,
                13,
                AuthFlavor::AuthUnix(params),
                AuthFlavor::AuthNone(None),
                &payload,
            )),
        );

        let mut cursor = Cursor::new(Vec::new());
        b.iter(|| {
            cursor.set_position(0);
            msg.serialise_into(&mut cursor)
                .expect("failed to serialise");
            let _ = black_box(&cursor);
        })
    });
}

criterion_group!(benches, auth, rpc_message);
criterion_main!(benches);
