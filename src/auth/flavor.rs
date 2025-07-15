use std::{
    convert::TryFrom,
    io::{Cursor, Write},
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::{auth::AuthUnixParams, Error, Opaque};

const AUTH_NONE: u32 = 0;
const AUTH_UNIX: u32 = 1;
const AUTH_SHORT: u32 = 2;

/// A set of basic auth flavor types
/// [described](https://tools.ietf.org/html/rfc5531#section-8.2) in RFC 5531.
///
/// The deprecated `AUTH_DH` is not supported, nor is GSS.
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
pub enum AuthFlavor<T>
where
    T: AsRef<[u8]>,
{
    /// `AUTH_NONE` with the opaque data the spec allows to be included
    /// (typically `None`).
    ///
    /// The provided opaque auth payload must not exceed 200 bytes in length.
    AuthNone(Option<T>),

    /// `AUTH_UNIX` and the fields it contains.
    AuthUnix(AuthUnixParams<T>),

    /// `AUTH_SHORT` and its opaque identifier
    ///
    /// The provided opaque auth payload must not exceed 200 bytes in length.
    AuthShort(T),

    /// An authentication credential unknown to this library, but possibly valid
    /// and acceptable by the server.
    Unknown {
        /// The discriminator for this undefined auth type.
        id: u32,

        /// The opaque data contained within the this flavour.
        ///
        /// This payload must not exceed 200 bytes in length.
        data: T,
    },
}

impl<'a> AuthFlavor<&'a [u8]> {
    pub(crate) fn from_cursor(r: &mut Cursor<&'a [u8]>) -> Result<Self, Error> {
        // Read the auth type
        let flavor = r.read_u32::<BigEndian>()?;

        let flavor = match flavor {
            AUTH_NONE => AuthFlavor::new_none(r)?,
            AUTH_UNIX => AuthFlavor::new_unix(r)?,
            AUTH_SHORT => AuthFlavor::new_short(r)?,
            // 3 => AuthFlavor::AuthDH,
            // 6 => AuthFlavor::RpcSecGSS,
            v => AuthFlavor::Unknown {
                id: v,
                data: Opaque::from_wire(r, 200)?.into_inner(),
            },
        };

        Ok(flavor)
    }

    fn new_none(r: &mut Cursor<&'a [u8]>) -> Result<Self, Error> {
        let payload = Opaque::from_wire(r, 200)?.into_inner();
        if payload.is_empty() {
            return Ok(AuthFlavor::AuthNone(None));
        }

        Ok(AuthFlavor::AuthNone(Some(payload)))
    }

    fn new_unix(r: &mut Cursor<&'a [u8]>) -> Result<Self, Error> {
        // TODO(dom): move this into callee
        let len = r.read_u32::<BigEndian>()?;
        if len > 200 {
            return Err(Error::InvalidLength);
        }

        Ok(AuthFlavor::AuthUnix(AuthUnixParams::from_cursor(r, len)?))
    }

    fn new_short(r: &mut Cursor<&'a [u8]>) -> Result<Self, Error> {
        Ok(AuthFlavor::AuthShort(
            Opaque::from_wire(r, 200)?.into_inner(),
        ))
    }
}

impl<T> AuthFlavor<T>
where
    T: AsRef<[u8]>,
{
    /// Serialises this auth flavor and writes it into buf.
    ///
    /// # Panics
    ///
    /// Panics if an associated byte payload is provided that exceeds 200 bytes.
    pub fn serialise_into<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        buf.write_u32::<BigEndian>(self.id())?;

        // Validate the payload length.
        assert!(self.associated_data_len() <= 200);

        // Write the actual auth data
        match self {
            // Opaque payloads serialise their length prefix internally.
            Self::AuthNone(Some(data)) | Self::AuthShort(data) | Self::Unknown { data, .. } => {
                Opaque::from_user_payload(data).serialise_into(&mut buf)
            }
            // No payload has a length of 0.
            Self::AuthNone(None) => {
                buf.write_u32::<BigEndian>(0)?;
                Ok(())
            }
            // Auth unix payloads have their length serialised by the caller.
            Self::AuthUnix(p) => {
                buf.write_u32::<BigEndian>(p.serialised_len())?;
                p.serialise_into(buf)
            }
        }
    }

    /// Returns the ID value used to identify the variant in the wire protocol.
    pub fn id(&self) -> u32 {
        match self {
            Self::AuthNone(_) => AUTH_NONE,
            Self::AuthUnix(_) => AUTH_UNIX,
            Self::AuthShort(_) => AUTH_SHORT,
            Self::Unknown { id, data: _ } => *id,
        }
    }

    /// Returns the byte length of the associated auth data, if any.
    pub fn associated_data_len(&self) -> u32 {
        match self {
            Self::AuthNone(Some(d)) => d.as_ref().len() as u32,
            Self::AuthNone(None) => 0,
            Self::AuthUnix(p) => p.associated_data_len(),
            Self::AuthShort(d) => d.as_ref().len() as u32,
            Self::Unknown { id: _id, data } => data.as_ref().len() as u32,
        }
    }

    /// Returns the on-wire length of this auth flavor once serialised,
    /// including discriminator and length values.
    pub fn serialised_len(&self) -> u32 {
        let mut l = 0;

        // Flavor discriminator
        l += 4;

        // Add the flavor size
        l += match self {
            #[allow(clippy::identity_op)]
            Self::AuthNone(None) => {
                // length prefix u32 + data length
                4 + 0
            }
            Self::AuthUnix(ref p) => 4 + p.serialised_len(),
            Self::Unknown { data, .. } | Self::AuthShort(data) | Self::AuthNone(Some(data)) => {
                Opaque::from_user_payload(data).serialised_len()
            }
        };

        l
    }
}

impl<'a> TryFrom<&'a [u8]> for AuthFlavor<&'a [u8]> {
    type Error = Error;

    fn try_from(v: &'a [u8]) -> Result<Self, Self::Error> {
        let mut c = Cursor::new(v);
        AuthFlavor::from_cursor(&mut c)
    }
}

#[cfg(feature = "bytes")]
impl TryFrom<crate::Bytes> for AuthFlavor<crate::Bytes> {
    type Error = Error;

    fn try_from(mut v: crate::Bytes) -> Result<Self, Self::Error> {
        use crate::bytes_ext::BytesReaderExt;

        let flavor = v.try_u32()?;
        let auth_data = v.try_array(200)?;

        let flavor = match flavor {
            AUTH_NONE if auth_data.is_empty() => Self::AuthNone(None),
            AUTH_NONE => Self::AuthNone(Some(auth_data)),
            AUTH_UNIX => {
                // Prevent malformed messages from including trailing data in
                // the AUTH_UNIX structure - the deserialised structure should
                // fully consume the opaque data associated with the AUTH_UNIX
                // variant.
                let should_consume = auth_data.len();
                let params = AuthUnixParams::try_from(auth_data)?;
                if params.serialised_len() as usize != should_consume {
                    return Err(Error::InvalidAuthData);
                }
                Self::AuthUnix(params)
            }
            AUTH_SHORT => Self::AuthShort(auth_data),
            // 3 => AuthFlavor::AuthDH,
            // 6 => AuthFlavor::RpcSecGSS,
            id => Self::Unknown {
                id,
                data: auth_data,
            },
        };

        Ok(flavor)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_auth_unix_unaligned_machinename<'a>() {
        #[rustfmt::skip]
        // Credentials
        //     Flavor: AUTH_UNIX (1)
        //     Length: 36
        //     Stamp: 0x00000000
        //     Machine Name: LAPTOP-1QQBPDGM
        //         length: 15
        //         contents: LAPTOP-1QQBPDGM
        //     UID: 0
        //     GID: 0
        //     Auxiliary GIDs (0)
        const RAW: [u8; 44] = hex!(
            "0000000100000024000000000000000f4c4150544f502d315151425044474d00000000000000000000000000"
        );

        let f: AuthFlavor<&'a [u8]> = RAW.as_ref().try_into().expect("failed to parse message");
        assert_eq!(f.serialised_len(), 44);
        assert_eq!(f.id(), AUTH_UNIX);
        assert_eq!(f.associated_data_len(), 27);

        let params = match f {
            AuthFlavor::AuthUnix(ref p) => p,
            _ => panic!("wrong auth"),
        };

        assert_eq!(params.uid(), 0);

        let mut c = Cursor::new(Vec::new());
        f.serialise_into(&mut c).expect("serialise failed");

        let buf = c.into_inner();
        assert_eq!(buf.as_slice(), RAW.as_ref());
    }

    #[test]
    fn test_auth_unix<'a>() {
        #[rustfmt::skip]
        // Credentials
        //     Flavor: AUTH_UNIX (1)
        //     Length: 84
        //     Stamp: 0x00000000
        //     Machine Name: <EMPTY>
        //         length: 0
        //         contents: <EMPTY>
        //     UID: 501
        //     GID: 20
        //     Auxiliary GIDs (16) [501, 12, 20, 61, 79, 80, 81, 98, 701, 33, 100, 204, 250, 395, 398, 399]
        //         GID: 501
        //         GID: 12
        //         GID: 20
        //         GID: 61
        //         GID: 79
        //         GID: 80
        //         GID: 81
        //         GID: 98
        //         GID: 701
        //         GID: 33
        //         GID: 100
        //         GID: 204
        //         GID: 250
        //         GID: 395
        //         GID: 398
        //         GID: 399
        const RAW: [u8; 92] = hex!(
            "00000001000000540000000000000000000001f50000001400000010000001f500
            00000c000000140000003d0000004f000000500000005100000062000002bd00000
            02100000064000000cc000000fa0000018b0000018e0000018f"
        );

        let f: AuthFlavor<&'a [u8]> = RAW.as_ref().try_into().expect("failed to parse message");
        assert_eq!(f.serialised_len(), 92);
        assert_eq!(f.id(), AUTH_UNIX);
        assert_eq!(f.associated_data_len(), 92 - 4 - 4 - 4 - 4); // - auth flavor - auth size - gids length - name length

        let params = match f {
            AuthFlavor::AuthUnix(ref p) => p,
            _ => panic!("wrong auth"),
        };

        assert_eq!(params.uid(), 501);

        let mut c = Cursor::new(Vec::new());
        f.serialise_into(&mut c).expect("serialise failed");

        let buf = c.into_inner();
        assert_eq!(buf.as_slice(), RAW.as_ref());
    }

    #[test]
    fn test_auth_none<'a>() {
        const RAW: [u8; 92] = hex!(
            "
            00 00 00 00
            00 00 00 54
            0000000000000000000001f50000001400000010000001f50000000c00000014000
            0003d0000004f000000500000005100000062000002bd0000002100000064000000
            cc000000fa0000018b0000018e0000018f"
        );

        let f: AuthFlavor<&'a [u8]> = RAW.as_ref().try_into().expect("failed to parse message");
        assert_eq!(f.serialised_len(), 92);
        assert_eq!(f.id(), AUTH_NONE);
        assert_eq!(f.associated_data_len(), 92 - 4 - 4);

        let data = match f {
            AuthFlavor::AuthNone(Some(ref p)) => p,
            _ => panic!("wrong auth"),
        };

        assert_eq!(data.len(), f.associated_data_len() as usize);
    }

    #[test]
    fn test_auth_short<'a>() {
        const RAW: [u8; 92] = hex!(
            "
            00 00 00 02
            00 00 00 54
            0000000000000000000001f50000001400000010000001f50000000c00000014000
            0003d0000004f000000500000005100000062000002bd0000002100000064000000
            cc000000fa0000018b0000018e0000018f"
        );

        let f: AuthFlavor<&'a [u8]> = RAW.as_ref().try_into().expect("failed to parse message");
        assert_eq!(f.serialised_len(), 92);
        assert_eq!(f.id(), AUTH_SHORT);
        assert_eq!(f.associated_data_len(), 92 - 4 - 4);

        let data = match f {
            AuthFlavor::AuthShort(ref p) => p,
            _ => panic!("wrong auth"),
        };

        assert_eq!(data.len(), f.associated_data_len() as usize);
    }

    #[test]
    fn test_auth_unknown<'a>() {
        const RAW: [u8; 92] = hex!(
            "
            00 00 00 FF
            00 00 00 54
            0000000000000000000001f50000001400000010000001f50000000c00000014000
            0003d0000004f000000500000005100000062000002bd0000002100000064000000
            cc000000fa0000018b0000018e0000018f"
        );

        let f: AuthFlavor<&'a [u8]> = RAW.as_ref().try_into().expect("failed to parse message");
        assert_eq!(f.serialised_len(), 92);
        assert_eq!(f.id(), 255);
        assert_eq!(f.associated_data_len(), 92 - 4 - 4);

        let (id, data) = match f {
            AuthFlavor::Unknown { id, data } => (id, data),
            _ => panic!("wrong auth"),
        };

        assert_eq!(id, f.id());
        assert_eq!(data.len(), f.associated_data_len() as usize);
    }
}
