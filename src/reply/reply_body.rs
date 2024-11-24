use std::{
    convert::TryFrom,
    io::{Cursor, Write},
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use super::{AcceptedReply, RejectedReply};
use crate::{Error, Opaque, SerializeOpaque};

const REPLY_ACCEPTED: u32 = 0;
const REPLY_DENIED: u32 = 1;

/// `ReplyBody` defines the response to an RPC invocation.
#[derive(Debug, PartialEq)]
pub enum ReplyBody<T, P>
where
    T: AsRef<[u8]> + SerializeOpaque,
    P: AsRef<[u8]>,
{
    /// The server accepted the request credentials.
    Accepted(AcceptedReply<T, P>),

    /// The server rejected the request credentials.
    Denied(RejectedReply),
}

impl<'a> ReplyBody<Opaque<'a, &'a [u8]>, &'a [u8]> {
    pub(crate) fn from_cursor(r: &mut Cursor<&'a [u8]>) -> Result<Self, Error> {
        match r.read_u32::<BigEndian>()? {
            REPLY_ACCEPTED => Ok(ReplyBody::Accepted(AcceptedReply::from_cursor(r)?)),
            REPLY_DENIED => Ok(ReplyBody::Denied(RejectedReply::from_cursor(r)?)),
            v => Err(Error::InvalidReplyType(v)),
        }
    }
}

impl<T, P> ReplyBody<T, P>
where
    T: AsRef<[u8]> + SerializeOpaque,
    P: AsRef<[u8]>,
{
    /// Serialises this `ReplyBody` into `buf`, advancing the cursor position by
    /// [`ReplyBody::serialised_len()`] bytes.
    pub fn serialise_into<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        match self {
            Self::Accepted(b) => {
                buf.write_u32::<BigEndian>(REPLY_ACCEPTED)?;
                b.serialise_into(buf)
            }
            Self::Denied(b) => {
                buf.write_u32::<BigEndian>(REPLY_DENIED)?;
                b.serialise_into(buf)
            }
        }
    }

    /// Returns the on-wire length of this `ReplyBody` once serialised,
    /// including the message header.
    pub fn serialised_len(&self) -> u32 {
        let mut len = 0;

        // Discriminator
        len += 4;

        // Variant length
        len += match self {
            Self::Accepted(b) => b.serialised_len(),
            Self::Denied(b) => b.serialised_len(),
        };

        len
    }
}

impl<'a> TryFrom<&'a [u8]> for ReplyBody<Opaque<'a, &'a [u8]>, &'a [u8]> {
    type Error = Error;

    fn try_from(v: &'a [u8]) -> Result<Self, Self::Error> {
        let mut c = Cursor::new(v);
        ReplyBody::from_cursor(&mut c)
    }
}

// #[cfg(feature = "bytes")]
// impl TryFrom<crate::Bytes> for ReplyBody<crate::Bytes, crate::Bytes> {
//     type Error = Error;

//     fn try_from(mut v: crate::Bytes) -> Result<Self, Self::Error> {
//         use crate::bytes_ext::BytesReaderExt;

//         match v.try_u32()? {
//             REPLY_ACCEPTED => Ok(Self::Accepted(AcceptedReply::try_from(v)?)),
//             REPLY_DENIED => Ok(Self::Denied(RejectedReply::try_from(v)?)),
//             v => Err(Error::InvalidReplyType(v)),
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use crate::auth::AuthFlavor;

    use super::*;

    // A compile-time test that ensures a payload can differ in type from the
    // auth buffer.
    #[test]
    fn test_differing_payload_type() {
        let binding = vec![42];
        let auth = AuthFlavor::AuthNone(Some(Opaque::from(binding.as_slice())));
        let payload = [42, 42, 42, 42];

        let _reply: ReplyBody<Opaque<'_, &[u8]>, [u8; 4]> = ReplyBody::Accepted(
            AcceptedReply::new(auth, crate::AcceptedStatus::Success(payload)),
        );
    }
}
