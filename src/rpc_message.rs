//! Contains types to implement the Open Network Computing RPC specification
//! defined in RFC 5531

use std::{
    convert::TryFrom,
    io::{Cursor, Write},
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Buf, Bytes};

use crate::{bytes_ext::BytesReaderExt, reply::ReplyBody, CallBody, Error};

const MSG_HEADER_LEN: usize = 4;
const LAST_FRAGMENT_BIT: u32 = 1 << 31;

const MESSAGE_TYPE_CALL: u32 = 0;
const MESSAGE_TYPE_REPLY: u32 = 1;

// TODO: serialise_ioslice() -> IoSliceBuffer

/// The type of RPC message.
#[derive(Debug, PartialEq)]
pub enum MessageType<T, P>
where
    T: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    /// This message is invoking an RPC.
    Call(CallBody<T, P>),
    /// This message is a response to an RPC request.
    Reply(ReplyBody<T, P>),
}

impl<'a> MessageType<&'a [u8], &'a [u8]> {
    /// Constructs a new `MessageType` by parsing the wire format read from `r`.
    ///
    /// `from_cursor` advances the position of `r` to the end of the
    /// `MessageType` structure.
    pub(crate) fn from_cursor(r: &mut Cursor<&'a [u8]>) -> Result<Self, Error> {
        match r.read_u32::<BigEndian>()? {
            MESSAGE_TYPE_CALL => Ok(MessageType::Call(CallBody::from_cursor(r)?)),
            MESSAGE_TYPE_REPLY => Ok(MessageType::Reply(ReplyBody::from_cursor(r)?)),
            v => Err(Error::InvalidMessageType(v)),
        }
    }
}

impl<T, P> MessageType<T, P>
where
    T: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    /// Serialises this `MessageType` into `buf`, advancing the cursor position
    /// by [`MessageType::serialised_len()`] bytes.
    pub fn serialise_into<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        match self {
            Self::Call(b) => {
                buf.write_u32::<BigEndian>(MESSAGE_TYPE_CALL)?;
                b.serialise_into(buf)?;
            }
            Self::Reply(b) => {
                buf.write_u32::<BigEndian>(MESSAGE_TYPE_REPLY)?;
                b.serialise_into(buf)?;
            }
        }

        Ok(())
    }

    /// Returns the on-wire length of this message once serialised, including
    /// the message header.
    pub fn serialised_len(&self) -> u32 {
        match self {
            Self::Call(c) => c.serialised_len() + 4,
            Self::Reply(r) => r.serialised_len() + 4,
        }
    }
}

impl TryFrom<Bytes> for MessageType<Bytes, Bytes> {
    type Error = Error;

    fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
        match v.try_u32()? {
            MESSAGE_TYPE_CALL => Ok(Self::Call(CallBody::try_from(v)?)),
            MESSAGE_TYPE_REPLY => Ok(Self::Reply(ReplyBody::try_from(v)?)),
            v => Err(Error::InvalidMessageType(v)),
        }
    }
}

/// An Open Network Computing RPC message, generic over a source of bytes (`T`)
/// and a payload buffer (`P`).
#[derive(Debug, PartialEq)]
pub struct RpcMessage<T, P>
where
    T: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    xid: u32,
    message_type: MessageType<T, P>,
}

impl<'a> RpcMessage<&'a [u8], &'a [u8]> {
    /// Deserialises a new [`RpcMessage`] from `buf`.
    ///
    /// Buf must contain exactly 1 message - if `buf` contains an incomplete
    /// message, or `buf` contains trailing bytes after the message
    /// [`Error::IncompleteMessage`] is returned.
    pub fn from_bytes(buf: &'a [u8]) -> Result<Self, Error> {
        // Unwrap the message header, validating the length of data.
        let data = unwrap_header(buf)?;

        // Wrap the data in a cursor for ease of parsing.
        let mut r = Cursor::new(data);

        let xid = r.read_u32::<BigEndian>()?;
        let message_type = MessageType::from_cursor(&mut r)?;

        let msg = RpcMessage { xid, message_type };

        // Detect messages that have more data than what was deserialised.
        //
        // This can occur if a message has a valid header length value for data,
        // but data contains more bytes than expected for this message type.
        //
        // +4 for the header which was
        let want_len = buf.len() as u32;
        if msg.serialised_len() != want_len {
            return Err(Error::IncompleteMessage {
                buffer_len: buf.len(),
                expected: msg.serialised_len() as usize,
            });
        }

        Ok(msg)
    }
}

impl<T, P> RpcMessage<T, P>
where
    T: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    /// Construct a new `RpcMessage` with the specified transaction ID and
    /// message body.
    pub fn new(xid: u32, message_type: MessageType<T, P>) -> Self {
        Self { xid, message_type }
    }

    /// Write this `RpcMessage` into `buf`, advancing the cursor to the end of
    /// the serialised message. `buf` must have capacity for at least
    /// [`RpcMessage::serialised_len()`] bytes from the current cursor position.
    ///
    /// This method allows the caller to specify the underlying buffer used to
    /// hold the serialised message to enable reuse and pooling.
    pub fn serialise_into<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        use std::io;

        // Build the message header.
        //
        // The header is a 31 bit number describing the length, and a "this is
        // the last fragment" flag.
        //
        // Because of this, serialised messages cannot exceed (2^31 - 1) bytes
        // (basically, the length cannot have the MSB set).
        if self.serialised_len() & LAST_FRAGMENT_BIT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message length exceeds maximum",
            ));
        }

        // Write the header.
        //
        // The header length (4 bytes) is not included in message length value.
        let header = (self.serialised_len() - 4) | LAST_FRAGMENT_BIT;
        buf.write_u32::<BigEndian>(header)?;

        // Write the XID
        buf.write_u32::<BigEndian>(self.xid)?;

        // Write the message body
        self.message_type.serialise_into(buf)
    }

    /// Serialise this `RpcMessage` into a new [`Vec`].
    ///
    /// The returned vec will be sized exactly to contain this message. Calling
    /// this method is the equivalent of:
    ///
    /// ```
    /// # use onc_rpc::{*, auth::*};
    /// # use std::io::Cursor;
    /// # let payload = vec![];
    /// # let msg = RpcMessage::<&[u8], &[u8]>::new(
    /// #     4242,
    /// #     MessageType::Call(CallBody::new(
    /// #         100000,
    /// #         42,
    /// #         13,
    /// #         AuthFlavor::AuthNone(None),
    /// #         AuthFlavor::AuthNone(None),
    /// #         &payload,
    /// #     )),
    /// # );
    /// #
    /// let mut buf = Vec::with_capacity(msg.serialised_len() as usize);
    /// let mut c = Cursor::new(buf);
    /// msg.serialise_into(&mut c);
    /// ```
    ///
    /// [`Vec`]: std::vec::Vec
    pub fn serialise(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Cursor::new(Vec::with_capacity(self.serialised_len() as usize));
        self.serialise_into(&mut buf)?;
        Ok(buf.into_inner())
    }

    /// Returns the on-wire length of this message once serialised, including
    /// the message header.
    pub fn serialised_len(&self) -> u32 {
        // +4 for xid, +4 for header
        self.message_type.serialised_len() + 4 + 4
    }

    /// The transaction ID for this request.
    pub fn xid(&self) -> u32 {
        self.xid
    }

    /// The [`MessageType`] contained in this request.
    pub fn message(&self) -> &MessageType<T, P> {
        &self.message_type
    }

    /// Returns the [`CallBody`] in this request, or `None` if this message is
    /// not a RPC call request.
    pub fn call_body(&self) -> Option<&CallBody<T, P>> {
        match self.message_type {
            MessageType::Call(ref b) => Some(b),
            _ => None,
        }
    }

    /// Returns the [`ReplyBody`] in this request, or `None` if this message is
    /// not a RPC response.
    pub fn reply_body(&self) -> Option<&ReplyBody<T, P>> {
        match self.message_type {
            MessageType::Reply(ref b) => Some(b),
            _ => None,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for RpcMessage<&'a [u8], &'a [u8]> {
    type Error = Error;

    fn try_from(v: &'a [u8]) -> Result<Self, Self::Error> {
        RpcMessage::from_bytes(v)
    }
}

impl TryFrom<Bytes> for RpcMessage<Bytes, Bytes> {
    type Error = Error;

    fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
        let original_buffer_len = v.len();

        // Read the message length from the header, and check v contains exactly
        // one message.
        let want = expected_message_len(v.as_ref())? as usize;
        if original_buffer_len != want {
            return Err(Error::IncompleteMessage {
                buffer_len: original_buffer_len,
                expected: want,
            });
        }

        // Advance past the header bytes
        v.advance(MSG_HEADER_LEN);

        let xid = v.try_u32()?;
        let message_type = MessageType::try_from(v)?;

        let msg = Self { xid, message_type };

        // Detect messages that have more data than what was deserialised.
        //
        // This can occur if a message has a valid header length value for data,
        // but data contains more bytes than expected for this message type.
        let parsed_len = msg.serialised_len() as usize;
        if parsed_len != original_buffer_len {
            return Err(Error::IncompleteMessage {
                buffer_len: original_buffer_len,
                expected: parsed_len,
            });
        }

        Ok(msg)
    }
}

/// Strip the 4 byte header from data, returning the rest of the message.
///
/// This function validates the message length value in the header matches the
/// length of `data`, and ensures this is not a fragmented message.
fn unwrap_header(data: &[u8]) -> Result<&[u8], Error> {
    let want = expected_message_len(data)?;

    // Validate the buffer contains the specified amount of data after the
    // header.
    let remaining_data = &data[MSG_HEADER_LEN..];

    if data.len() != want as usize {
        return Err(Error::IncompleteMessage {
            buffer_len: data.len(),
            expected: want as usize,
        });
    }

    Ok(remaining_data)
}

/// Reads the message header from data, and returns the expected wire length of
/// the RPC message.
///
/// `data` must contain at least 4 bytes, and must be the start of an RPC
/// message for this call to return valid data. If the message does not have the
/// `last fragment` bit set, [`Error::Fragmented`] is returned.
pub fn expected_message_len(data: &[u8]) -> Result<u32, Error> {
    if data.len() < MSG_HEADER_LEN {
        return Err(Error::IncompleteHeader);
    }

    // Read the 4 byte fragment header.
    //
    // RFC1831 defines it as a big endian, 4 byte unsigned number:
    //
    // > The number encodes two values -- a boolean which indicates whether the
    // > fragment is the last fragment of the record (bit value 1 implies the
    // > fragment is the last fragment) and a 31-bit unsigned binary value which is
    // > the length in bytes of the fragment's data.  The boolean value is the
    // > highest-order bit of the header; the length is the 31 low-order bits.
    //
    let header = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    // Ensure the "last fragment" bit is set
    if header & LAST_FRAGMENT_BIT == 0 {
        return Err(Error::Fragmented);
    }

    // +4 for the header bytes not counted in the "length" value.
    Ok((header & !LAST_FRAGMENT_BIT) + 4)
}

/// Returns a subslice of len bytes from c without copying if it is safe to do
/// so.
pub(crate) fn read_slice_bytes<'a>(c: &mut Cursor<&'a [u8]>, len: u32) -> Result<&'a [u8], Error> {
    let data = *c.get_ref();
    let start = c.position() as usize;
    let end = start + len as usize;

    // Validate the subslice is within the data buffer
    if end > data.len() {
        return Err(Error::InvalidLength);
    }

    c.set_position(end as u64);
    Ok(&data[start..end])
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use smallvec::smallvec;

    use super::*;
    use crate::{auth::AuthFlavor, AcceptedStatus};

    #[test]
    fn test_unwrap_header() {
        let x = hex!(
            "80 00 01 1c 265ec0fd0000000000000002000186a30000000400000001000000
			01000000540000000000000000000001f50000001400000010000001f50000000c0
			00000140000003d0000004f000000500000005100000062000002bd000000210000
			0064000000cc000000fa0000018b0000018e0000018f00000000000000000000000
			c736574636c696420202020200000000000000001000000235ed267a20000683900
			00004b00000000f8ffc247f4fb10020801c0a801bd00000000000000003139322e3
			136382e312e3138393a2f686f6d652f646f6d002f55736572732f646f6d2f446573
			6b746f702f6d6f756e7400004e4653430000000374637000000000153139322e313
			6382e312e3138382e3233382e32333500000000000002"
        );

        let want = &x[4..];

        assert_eq!(unwrap_header(&x), Ok(want));
    }

    #[test]
    fn test_unwrap_header_validates_expected() {
        let x = hex!("80");

        assert_eq!(unwrap_header(&x).unwrap_err(), Error::IncompleteHeader);
    }

    #[test]
    fn test_unwrap_header_validates_message_len() {
        let x = hex!("80 00 01 1c 265ec0fd0000000000000002");

        assert_eq!(
            unwrap_header(&x),
            Err(Error::IncompleteMessage {
                buffer_len: 16,
                expected: 288,
            })
        );
    }

    #[test]
    fn test_unwrap_header_validates_fragment_bit() {
        let x = hex!("00 00 01 1c 265ec0fd0000000000000002");

        assert_eq!(unwrap_header(&x), Err(Error::Fragmented));
    }

    #[test]
    fn test_rpcmessage_auth_unix() {
        // Frame 3: 354 bytes on wire (2832 bits), 354 bytes captured (2832 bits) on interface en0, id 0
        // Ethernet II, Src: Apple_47:f4:fb (f8:ff:c2:47:f4:fb), Dst: PcsCompu_76:48:20 (08:00:27:76:48:20)
        // Internet Protocol Version 4, Src: client (192.168.1.188), Dst: server (192.168.1.189)
        // Transmission Control Protocol, Src Port: 61162, Dst Port: 2049, Seq: 69, Ack: 29, Len: 288
        // Remote Procedure Call, Type:Call XID:0x265ec0fd
        //     Fragment header: Last fragment, 284 bytes
        //         1... .... .... .... .... .... .... .... = Last Fragment: Yes
        //         .000 0000 0000 0000 0000 0001 0001 1100 = Fragment Length: 284
        //     XID: 0x265ec0fd (643743997)
        //     Message Type: Call (0)
        //     RPC Version: 2
        //     Program: NFS (100003)
        //     Program Version: 4
        //     Procedure: COMPOUND (1)
        //     [The reply to this request is in frame 4]
        //     Credentials
        //         Flavor: AUTH_UNIX (1)
        //         Length: 84

        //         Stamp: 0x00000000
        //         Machine Name: <EMPTY>
        //             length: 0
        //             contents: <EMPTY>
        //         UID: 501
        //         GID: 20
        //         Auxiliary GIDs (16) [501, 12, 20, 61, 79, 80, 81, 98, 701, 33, 100, 204, 250, 395, 398, 399]
        //             GID: 501
        //             GID: 12
        //             GID: 20
        //             GID: 61
        //             GID: 79
        //             GID: 80
        //             GID: 81
        //             GID: 98
        //             GID: 701
        //             GID: 33
        //             GID: 100
        //             GID: 204
        //             GID: 250
        //             GID: 395
        //             GID: 398
        //             GID: 399

        //     Verifier
        //         Flavor: AUTH_NULL (0)
        //         Length: 0
        // Network File System, Ops(1): SETCLIENTID
        //     [Program Version: 4]
        //     [V4 Procedure: COMPOUND (1)]
        //     Tag: setclid
        //         length: 12
        //         contents: setclid
        //     minorversion: 0
        //     Operations (count: 1): SETCLIENTID
        //         Opcode: SETCLIENTID (35)
        //             client
        //                 verifier: 0x5ed267a200006839
        //                 id: <DATA>
        //                     length: 75
        //                     contents: <DATA>
        //                     fill bytes: opaque data
        //             callback
        //                 cb_program: 0x4e465343
        //                 cb_location
        //                     r_netid: tcp
        //                         length: 3
        //                         contents: tcp
        //                         fill bytes: opaque data
        //                     r_addr: 192.168.1.188.238.235
        //                         length: 21
        //                         contents: 192.168.1.188.238.235
        //                         fill bytes: opaque data
        //                     [IPv4 address 192.168.1.188, protocol=tcp, port=61163]
        //             callback_ident: 0x00000002
        //     [Main Opcode: SETCLIENTID (35)]

        const RAW: [u8; 288] = hex!(
            "8000011c265ec0fd0000000000000002000186a300000004000000010000000100
			0000540000000000000000000001f50000001400000010000001f50000000c00000
			0140000003d0000004f000000500000005100000062000002bd0000002100000064
			000000cc000000fa0000018b0000018e0000018f00000000000000000000000c736
			574636c696420202020200000000000000001000000235ed267a200006839000000
			4b00000000f8ffc247f4fb10020801c0a801bd00000000000000003139322e31363
			82e312e3138393a2f686f6d652f646f6d002f55736572732f646f6d2f4465736b74
			6f702f6d6f756e7400004e4653430000000374637000000000153139322e3136382
			e312e3138382e3233382e32333500000000000002"
        );

        assert_eq!(expected_message_len(RAW.as_ref()).unwrap(), 288);

        let msg = RpcMessage::from_bytes(RAW.as_ref()).expect("failed to parse message");
        assert_eq!(msg.xid(), 643743997);
        assert_eq!(msg.serialised_len(), 288);

        let body = msg.call_body().expect("not a call rpc");
        assert_eq!(body.rpc_version(), 2);
        assert_eq!(body.program(), 100003);
        assert_eq!(body.program_version(), 4);
        assert_eq!(body.procedure(), 1);

        assert_eq!(body.auth_credentials().serialised_len(), 92);
        let auth = match *body.auth_credentials() {
            AuthFlavor::AuthUnix(ref v) => v,
            _ => panic!("unexpected auth type"),
        };

        assert_eq!(auth.stamp(), 0x00000000);
        assert_eq!(auth.machine_name_str(), "");
        assert_eq!(auth.uid(), 501);
        assert_eq!(auth.gid(), 20);
        assert_eq!(
            auth.gids(),
            Some(&smallvec![
                501, 12, 20, 61, 79, 80, 81, 98, 701, 33, 100, 204, 250, 395, 398, 399
            ])
        );
        assert_eq!(auth.serialised_len(), 84);

        assert_eq!(*body.auth_verifier(), AuthFlavor::AuthNone(None));

        let payload = hex!(
            "0000000c736574636c696420202020200000000000000001000000235ed267a200
			0068390000004b00000000f8ffc247f4fb10020801c0a801bd00000000000000003
			139322e3136382e312e3138393a2f686f6d652f646f6d002f55736572732f646f6d
			2f4465736b746f702f6d6f756e7400004e465343000000037463700000000015313
			9322e3136382e312e3138382e3233382e32333500000000000002"
        );

        assert_eq!(body.payload().as_ref(), payload.as_ref());

        let serialised = msg.serialise().expect("failed to serialise");
        assert_eq!(serialised.as_slice(), RAW.as_ref());
    }

    #[test]
    fn test_rpcmessage_auth_unix_bytes() {
        // Frame 3: 354 bytes on wire (2832 bits), 354 bytes captured (2832 bits) on interface en0, id 0
        // Ethernet II, Src: Apple_47:f4:fb (f8:ff:c2:47:f4:fb), Dst: PcsCompu_76:48:20 (08:00:27:76:48:20)
        // Internet Protocol Version 4, Src: client (192.168.1.188), Dst: server (192.168.1.189)
        // Transmission Control Protocol, Src Port: 61162, Dst Port: 2049, Seq: 69, Ack: 29, Len: 288
        // Remote Procedure Call, Type:Call XID:0x265ec0fd
        //     Fragment header: Last fragment, 284 bytes
        //         1... .... .... .... .... .... .... .... = Last Fragment: Yes
        //         .000 0000 0000 0000 0000 0001 0001 1100 = Fragment Length: 284
        //     XID: 0x265ec0fd (643743997)
        //     Message Type: Call (0)
        //     RPC Version: 2
        //     Program: NFS (100003)
        //     Program Version: 4
        //     Procedure: COMPOUND (1)
        //     [The reply to this request is in frame 4]
        //     Credentials
        //         Flavor: AUTH_UNIX (1)
        //         Length: 84

        //         Stamp: 0x00000000
        //         Machine Name: <EMPTY>
        //             length: 0
        //             contents: <EMPTY>
        //         UID: 501
        //         GID: 20
        //         Auxiliary GIDs (16) [501, 12, 20, 61, 79, 80, 81, 98, 701, 33, 100, 204, 250, 395, 398, 399]
        //             GID: 501
        //             GID: 12
        //             GID: 20
        //             GID: 61
        //             GID: 79
        //             GID: 80
        //             GID: 81
        //             GID: 98
        //             GID: 701
        //             GID: 33
        //             GID: 100
        //             GID: 204
        //             GID: 250
        //             GID: 395
        //             GID: 398
        //             GID: 399

        //     Verifier
        //         Flavor: AUTH_NULL (0)
        //         Length: 0
        // Network File System, Ops(1): SETCLIENTID
        //     [Program Version: 4]
        //     [V4 Procedure: COMPOUND (1)]
        //     Tag: setclid
        //         length: 12
        //         contents: setclid
        //     minorversion: 0
        //     Operations (count: 1): SETCLIENTID
        //         Opcode: SETCLIENTID (35)
        //             client
        //                 verifier: 0x5ed267a200006839
        //                 id: <DATA>
        //                     length: 75
        //                     contents: <DATA>
        //                     fill bytes: opaque data
        //             callback
        //                 cb_program: 0x4e465343
        //                 cb_location
        //                     r_netid: tcp
        //                         length: 3
        //                         contents: tcp
        //                         fill bytes: opaque data
        //                     r_addr: 192.168.1.188.238.235
        //                         length: 21
        //                         contents: 192.168.1.188.238.235
        //                         fill bytes: opaque data
        //                     [IPv4 address 192.168.1.188, protocol=tcp, port=61163]
        //             callback_ident: 0x00000002
        //     [Main Opcode: SETCLIENTID (35)]

        const RAW: [u8; 288] = hex!(
            "8000011c265ec0fd0000000000000002000186a300000004000000010000000100
			0000540000000000000000000001f50000001400000010000001f50000000c00000
			0140000003d0000004f000000500000005100000062000002bd0000002100000064
			000000cc000000fa0000018b0000018e0000018f00000000000000000000000c736
			574636c696420202020200000000000000001000000235ed267a200006839000000
			4b00000000f8ffc247f4fb10020801c0a801bd00000000000000003139322e31363
			82e312e3138393a2f686f6d652f646f6d002f55736572732f646f6d2f4465736b74
			6f702f6d6f756e7400004e4653430000000374637000000000153139322e3136382
			e312e3138382e3233382e32333500000000000002"
        );

        let static_raw: &'static [u8] = Box::leak(Box::new(RAW));

        assert_eq!(expected_message_len(static_raw).unwrap(), 288);

        let msg = RpcMessage::try_from(Bytes::from(static_raw)).expect("failed to parse message");
        assert_eq!(msg.xid(), 643743997);
        assert_eq!(msg.serialised_len(), 288);

        let body = msg.call_body().expect("not a call rpc");
        assert_eq!(body.rpc_version(), 2);
        assert_eq!(body.program(), 100003);
        assert_eq!(body.program_version(), 4);
        assert_eq!(body.procedure(), 1);

        assert_eq!(body.auth_credentials().serialised_len(), 92);
        let auth = match body.auth_credentials() {
            AuthFlavor::AuthUnix(ref v) => v,
            v => panic!("unexpected auth type {:?}", v),
        };

        assert_eq!(auth.stamp(), 0x00000000);
        assert_eq!(auth.machine_name_str(), "");
        assert_eq!(auth.uid(), 501);
        assert_eq!(auth.gid(), 20);
        assert_eq!(
            auth.gids(),
            Some(&smallvec![
                501, 12, 20, 61, 79, 80, 81, 98, 701, 33, 100, 204, 250, 395, 398, 399
            ])
        );
        assert_eq!(auth.serialised_len(), 84);

        assert_eq!(*body.auth_verifier(), AuthFlavor::AuthNone(None));

        let payload = hex!(
            "0000000c736574636c696420202020200000000000000001000000235ed267a200
			0068390000004b00000000f8ffc247f4fb10020801c0a801bd00000000000000003
			139322e3136382e312e3138393a2f686f6d652f646f6d002f55736572732f646f6d
			2f4465736b746f702f6d6f756e7400004e465343000000037463700000000015313
			9322e3136382e312e3138382e3233382e32333500000000000002"
        );

        assert_eq!(body.payload(), payload.as_ref());

        let serialised = msg.serialise().expect("failed to serialise");
        assert_eq!(serialised.as_slice(), RAW.as_ref());
    }

    #[test]
    fn test_rpcmessage_auth_unix_empty<'a>() {
        // Remote Procedure Call, Type:Call XID:0x265ec106
        //     Fragment header: Last fragment, 152 bytes
        //         1... .... .... .... .... .... .... .... = Last Fragment: Yes
        //         .000 0000 0000 0000 0000 0000 1001 1000 = Fragment Length: 152
        //     XID: 0x265ec106 (643744006)
        //     Message Type: Call (0)
        //     RPC Version: 2
        //     Program: NFS (100003)
        //     Program Version: 4
        //     Procedure: COMPOUND (1)
        //     [The reply to this request is in frame 22]
        //     Credentials
        //         Flavor: AUTH_UNIX (1)
        //         Length: 24
        //         Stamp: 0x00000000
        //         Machine Name: <EMPTY>
        //             length: 0
        //             contents: <EMPTY>
        //         UID: 0
        //         GID: 0
        //         Auxiliary GIDs (1) [0]
        //             GID: 0
        //     Verifier
        //         Flavor: AUTH_NULL (0)
        //         Length: 0
        // Network File System, Ops(3): PUTFH, ACCESS, GETATTR
        //     [Program Version: 4]
        //     [V4 Procedure: COMPOUND (1)]
        //     Tag: access
        //         length: 12
        //         contents: access
        //     minorversion: 0
        //     Operations (count: 3): PUTFH, ACCESS, GETATTR
        //         Opcode: PUTFH (22)
        //             FileHandle
        //                 length: 31
        //                 [hash (CRC-32): 0x4bcbccda]
        //                 FileHandle: 4300004d1a436f6c452240ea4c70a1b52d7f97418e6601a1…
        //         Opcode: ACCESS (3), [Check: RD LU MD XT DL XE]
        //             Check access: 0x3f
        //                 .... ...1 = 0x001 READ: allowed?
        //                 .... ..1. = 0x002 LOOKUP: allowed?
        //                 .... .1.. = 0x004 MODIFY: allowed?
        //                 .... 1... = 0x008 EXTEND: allowed?
        //                 ...1 .... = 0x010 DELETE: allowed?
        //                 ..1. .... = 0x020 EXECUTE: allowed?
        //         Opcode: GETATTR (9)
        //             Attr mask[0]: 0x1010011a (Type, Change, Size, FSID, FileId, MaxLink)
        //                 reqd_attr: Type (1)
        //                 reqd_attr: Change (3)
        //                 reqd_attr: Size (4)
        //                 reqd_attr: FSID (8)
        //                 reco_attr: FileId (20)
        //                 reco_attr: MaxLink (28)
        //             Attr mask[1]: 0x00b0a23a (Mode, NumLinks, Owner, Owner_Group, RawDev, Space_Used, Time_Access, Time_Metadata, Time_Modify, Mounted_on_FileId)
        //                 reco_attr: Mode (33)
        //                 reco_attr: NumLinks (35)
        //                 reco_attr: Owner (36)
        //                 reco_attr: Owner_Group (37)
        //                 reco_attr: RawDev (41)
        //                 reco_attr: Space_Used (45)
        //                 reco_attr: Time_Access (47)
        //                 reco_attr: Time_Metadata (52)
        //                 reco_attr: Time_Modify (53)
        //                 reco_attr: Mounted_on_FileId (55)
        //     [Main Opcode: ACCESS (3)]

        const RAW: [u8; 156] = hex!(
            "80000098265ec1060000000000000002000186a300000004000000010000000100
			0000180000000000000000000000000000000000000001000000000000000000000
			0000000000c6163636573732020202020200000000000000003000000160000001f
			4300004d1a436f6c452240ea4c70a1b52d7f97418e6601a10e02009cf2d59c00000
			000030000003f00000009000000021010011a00b0a23a"
        );

        let msg = RpcMessage::from_bytes(RAW.as_ref()).expect("failed to parse message");
        assert_eq!(msg.xid(), 643744006);
        assert_eq!(msg.serialised_len(), 156);

        let body = msg.call_body().expect("not a call rpc");
        assert_eq!(body.rpc_version(), 2);
        assert_eq!(body.program(), 100003);
        assert_eq!(body.program_version(), 4);
        assert_eq!(body.procedure(), 1);

        assert_eq!(body.auth_credentials().serialised_len(), 32);
        let params = match *body.auth_credentials() {
            AuthFlavor::AuthUnix(ref v) => v,
            ref v => panic!("unexpected auth type {:?}", v),
        };

        assert_eq!(params.stamp(), 0x00000000);
        assert_eq!(params.machine_name_str(), "");
        assert_eq!(params.uid(), 0);
        assert_eq!(params.gid(), 0);
        assert_eq!(params.serialised_len(), 24);
        assert_eq!(params.gids(), Some(&smallvec![0]));

        assert_eq!(*body.auth_verifier(), AuthFlavor::AuthNone(None));
        assert_eq!(body.auth_verifier().serialised_len(), 8);

        assert_eq!(body.payload().len(), 88);

        let serialised = msg.serialise().expect("failed to serialise");
        assert_eq!(serialised.as_slice(), RAW.as_ref());
    }

    #[test]
    fn test_rpcmessage_reply<'a>() {
        // Remote Procedure Call, Type:Reply XID:0x265ec0fd
        //     Fragment header: Last fragment, 72 bytes
        //         1... .... .... .... .... .... .... .... = Last Fragment: Yes
        //         .000 0000 0000 0000 0000 0000 0100 1000 = Fragment Length: 72
        //     XID: 0x265ec0fd (643743997)
        //     Message Type: Reply (1)
        //     [Program: NFS (100003)]
        //     [Program Version: 4]
        //     [Procedure: COMPOUND (1)]
        //     Reply State: accepted (0)
        //     [This is a reply to a request in frame 3]
        //     [Time from request: 0.000159000 seconds]
        //     Verifier
        //         Flavor: AUTH_NULL (0)
        //         Length: 0
        //     Accept State: RPC executed successfully (0)

        const RAW: [u8; 76] = hex!(
            "80000048265ec0fd00000001000000000000000000000000000000000000000000
            00000c736574636c696420202020200000000100000023000000005ed2672e00000
            0020200000000000000"
        );

        let msg = RpcMessage::from_bytes(RAW.as_ref()).expect("failed to parse message");
        assert_eq!(msg.xid(), 643743997);
        assert_eq!(msg.serialised_len(), 76);

        let body = match msg.reply_body().expect("not a call rpc") {
            ReplyBody::Accepted(b) => b,
            _ => panic!("wrong reply type"),
        };
        assert_eq!(body.serialised_len(), 60);

        match body.status() {
            AcceptedStatus::Success(data) => {
                assert_eq!(data.len(), 48);
            }
            _ => panic!("wrong reply status type"),
        };

        match body.auth_verifier() {
            AuthFlavor::AuthNone(None) => {}
            _ => panic!("wrong verifier type"),
        };

        let buf = msg.serialise().expect("failed to serialise");
        assert_eq!(buf.as_slice(), RAW.as_ref());
    }

    #[test]
    fn test_rpcmessage_reply_bytes<'a>() {
        // Remote Procedure Call, Type:Reply XID:0x265ec0fd
        //     Fragment header: Last fragment, 72 bytes
        //         1... .... .... .... .... .... .... .... = Last Fragment: Yes
        //         .000 0000 0000 0000 0000 0000 0100 1000 = Fragment Length: 72
        //     XID: 0x265ec0fd (643743997)
        //     Message Type: Reply (1)
        //     [Program: NFS (100003)]
        //     [Program Version: 4]
        //     [Procedure: COMPOUND (1)]
        //     Reply State: accepted (0)
        //     [This is a reply to a request in frame 3]
        //     [Time from request: 0.000159000 seconds]
        //     Verifier
        //         Flavor: AUTH_NULL (0)
        //         Length: 0
        //     Accept State: RPC executed successfully (0)

        const RAW: [u8; 76] = hex!(
            "80000048265ec0fd00000001000000000000000000000000000000000000000000
            00000c736574636c696420202020200000000100000023000000005ed2672e00000
            0020200000000000000"
        );

        let static_raw: &'static [u8] = Box::leak(Box::new(RAW));

        let msg = RpcMessage::try_from(Bytes::from(static_raw)).expect("failed to parse message");
        assert_eq!(msg.xid(), 643743997);
        assert_eq!(msg.serialised_len(), 76);

        let body = match msg.reply_body().expect("not a call rpc") {
            ReplyBody::Accepted(b) => b,
            _ => panic!("wrong reply type"),
        };
        assert_eq!(body.serialised_len(), 60);

        match body.status() {
            AcceptedStatus::Success(data) => {
                assert_eq!(data.len(), 48);
            }
            _ => panic!("wrong reply status type"),
        };

        match body.auth_verifier() {
            AuthFlavor::AuthNone(None) => {}
            _ => panic!("wrong verifier type"),
        };

        let buf = msg.serialise().expect("failed to serialise");
        assert_eq!(buf.as_slice(), RAW.as_ref());
    }

    #[test]
    fn test_fuzz_message_too_long_for_type<'a>() {
        const RAW: [u8; 39] = hex!(
            "800000232323232300000001000000000000000000000000000000010302
            232323232300232300"
        );

        let msg = RpcMessage::from_bytes(RAW.as_ref());
        match msg {
            Err(Error::IncompleteMessage {
                buffer_len: b,
                expected: e,
            }) => {
                assert_eq!(b, 39);
                assert_eq!(e, 28);
            }
            v => panic!("expected incomplete error, got {:?}", v),
        }
    }

    #[test]
    fn test_fuzz_message_too_long_for_type_bytes<'a>() {
        const RAW: [u8; 39] = hex!(
            "800000232323232300000001000000000000000000000000000000010302
            232323232300232300"
        );

        let msg = RpcMessage::try_from(Bytes::copy_from_slice(RAW.as_ref()));
        match msg {
            Err(Error::IncompleteMessage {
                buffer_len: b,
                expected: e,
            }) => {
                assert_eq!(b, 39);
                assert_eq!(e, 28);
            }
            v => panic!("expected incomplete error, got {:?}", v),
        }
    }

    #[test]
    fn test_ioslice_payload() {
        use std::io::IoSlice;

        let buf1 = [1; 8];
        let ioslice = IoSlice::new(&buf1);

        let body = CallBody::<&[u8], _>::new(
            1,
            2,
            3,
            AuthFlavor::AuthNone(None),
            AuthFlavor::AuthNone(None),
            ioslice.as_ref(),
        );

        let msg = RpcMessage::new(42, MessageType::Call(body));

        assert_eq!(msg.call_body().unwrap().payload(), &buf1);
    }
}
