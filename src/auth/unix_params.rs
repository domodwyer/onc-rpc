use crate::bytes_ext::BytesReaderExt;
use crate::read_slice_bytes;
use crate::Error;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use bytes::Bytes;
use smallvec::SmallVec;
use std::convert::TryFrom;
use std::io::{Cursor, Write};

/// `AuthUnixParams` represents the structures referred to as both `AUTH_UNIX`
/// and `AUTH_SYS` in the various RFCs, used to idenitfy the client as a Unix
/// user.
///
/// The structure is implemented as specified in `APPENDIX A` of
/// [RFC1831](https://tools.ietf.org/html/rfc1831).
///
/// These values are trivial to forge and provide no actual security.
#[derive(Debug, PartialEq, Clone)]
pub struct AuthUnixParams<T> {
    stamp: u32,
    machine_name: T,
    uid: u32,
    gid: u32,
    gids: Option<SmallVec<[u32; 16]>>,
}

impl<'a> AuthUnixParams<&'a [u8]> {
    /// Constructs a new `AuthUnixParams` by parsing the wire format read from
    /// `r`, validating it has read exactly `expected_len` number of bytes.
    ///
    /// `from_cursor` advances the position of `r` to the end of the `AUTH_UNIX`
    /// structure.
    pub(crate) fn from_cursor(r: &mut Cursor<&'a [u8]>, expected_len: u32) -> Result<Self, Error> {
        // Get the start length the parser can validate it read the expected
        // amount of data at the end of the function
        let start_pos = r.position();

        // Read the stamp
        let stamp = r.read_u32::<BigEndian>()?;

        // Read the variable length name
        let name_len = r.read_u32::<BigEndian>()?;
        if name_len > 16 {
            return Err(Error::InvalidLength);
        }

        // Read the string without copying
        let name = read_slice_bytes(r, name_len)?;

        // UID & GID
        let uid = r.read_u32::<BigEndian>()?;
        let gid = r.read_u32::<BigEndian>()?;

        // Gids
        let gids_count = r.read_u32::<BigEndian>()? as usize;
        let gids = match gids_count {
            0 => None,
            c if c <= 16 => {
                let mut v = SmallVec::<[u32; 16]>::new();
                for _ in 0..c {
                    v.push(r.read_u32::<BigEndian>()?);
                }
                Some(v)
            }
            _ => return Err(Error::InvalidAuthData),
        };

        // Validate the parser read the expected amount of data to construct
        // this type
        if (r.position() - start_pos) != expected_len as u64 {
            return Err(Error::InvalidAuthData);
        }

        Ok(AuthUnixParams {
            stamp,
            machine_name: name,
            uid,
            gid,
            gids,
        })
    }
}

impl<T> AuthUnixParams<T>
where
    T: AsRef<[u8]>,
{
    /// Initialise a new `AuthUnixParams` instance containing the specified unix
    /// account identifiers.
    pub fn new(
        stamp: u32,
        machine_name: T,
        uid: u32,
        gid: u32,
        gids: Option<SmallVec<[u32; 16]>>,
    ) -> Self {
        AuthUnixParams {
            stamp,
            machine_name,
            uid,
            gid,
            gids,
        }
    }

    /// Serialises this `AuthUnixParams` into `buf`, advancing the cursor
    /// position by [`serialised_len`](AuthUnixParams::serialised_len) bytes.
    pub fn serialise_into<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        buf.write_u32::<BigEndian>(self.stamp)?;
        buf.write_u32::<BigEndian>(self.machine_name.as_ref().len() as u32)?;
        buf.write_all(self.machine_name.as_ref())?;
        buf.write_u32::<BigEndian>(self.uid)?;
        buf.write_u32::<BigEndian>(self.gid)?;

        // Gids array length prefix
        buf.write_u32::<BigEndian>(self.gids.as_ref().map_or(0, |v| v.len() as u32))?;

        // Gids values
        if let Some(gids) = self.gids.as_ref() {
            for g in gids {
                buf.write_u32::<BigEndian>(*g)?;
            }
        }
        Ok(())
    }

    /// An arbitrary ID generated by the caller.
    pub fn stamp(&self) -> u32 {
        self.stamp
    }

    /// The hostname of the caller's machine.
    pub fn machine_name(&self) -> &T {
        &self.machine_name
    }

    /// The hostname of the caller's machine as a reference to a UTF8 string.
    ///
    /// # Panics
    ///
    /// If the machine name cannot be expressed as a valid UTF8 string, this
    /// method panics.
    pub fn machine_name_str(&self) -> &str {
        std::str::from_utf8(self.machine_name.as_ref()).unwrap()
    }

    /// The caller's Unix user ID.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The caller's primary Unix group ID.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns a copy of the `gids` array, a set of Unix group IDs the caller
    /// is a member of.
    pub fn gids(&self) -> Option<&SmallVec<[u32; 16]>> {
        self.gids.as_ref()
    }

    /// Returns the on-wire length of this message once serialised, including
    /// the message header.
    pub fn serialised_len(&self) -> u32 {
        // uid, gid, stamp
        let mut l = std::mem::size_of::<u32>() * 3;

        // machine_name length u32 + bytes
        l += std::mem::size_of::<u32>() + self.machine_name.as_ref().len();

        // gids length prefix u32 + values
        l += (self.gids.as_ref().map_or(0, |g| g.len()) + 1) * std::mem::size_of::<u32>();

        l as u32
    }
}

impl TryFrom<Bytes> for AuthUnixParams<Bytes> {
    type Error = Error;

    fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
        let stamp = v.try_u32()?;

        let name = v.try_array(16)?;
        let uid = v.try_u32()?;
        let gid = v.try_u32()?;

        let gids_count = v.try_u32()? as usize;
        let gids = match gids_count {
            0 => None,
            c if c <= 16 => {
                let mut vec = SmallVec::<[u32; 16]>::new();
                for _ in 0..c {
                    vec.push(v.try_u32()?);
                }
                Some(vec)
            }
            _ => return Err(Error::InvalidAuthData),
        };

        Ok(AuthUnixParams {
            stamp,
            machine_name: name,
            uid,
            gid,
            gids,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use smallvec::smallvec;

    #[test]
    fn test_serialise_deserialise() {
        let gids =
            smallvec![501, 12, 20, 61, 79, 80, 81, 98, 701, 33, 100, 204, 250, 395, 398, 399,];
        let params = AuthUnixParams::new(0, b"".as_ref(), 501, 20, Some(gids));

        let mut buf = Cursor::new(Vec::new());
        params
            .serialise_into(&mut buf)
            .expect("failed to serialise");

        #[rustfmt::skip]
        // Known good wire value trimmed of flavor + length bytes.
        //
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
        //
        let want = hex!(
            "0000000000000000000001f50000001400000010000001f50000000c0000001400
            00003d0000004f000000500000005100000062000002bd000000210000006400000
            0cc000000fa0000018b0000018e0000018f"
        );

        let buf = buf.into_inner();
        assert_eq!(want.len(), buf.len());
        assert_eq!(want.as_ref(), buf.as_slice());

        let mut c = Cursor::new(want.as_ref());
        let s = AuthUnixParams::from_cursor(&mut c, 84).expect("deserialise failed");

        assert_eq!(s.serialised_len(), 84);
        assert_eq!(params, s);
    }

    #[test]
    fn test_empty() {
        // Known good wire value trimmed of flavor + length bytes.
        //
        // Credentials
        //     Flavor: AUTH_UNIX (1)
        //     Length: 24
        //     Stamp: 0x00000000
        //     Machine Name: <EMPTY>
        //         length: 0
        //         contents: <EMPTY>
        //     UID: 0
        //     GID: 0
        //     Auxiliary GIDs (1) [0]
        //         GID: 0
        let want = hex!("000000000000000000000000000000000000000100000000");
        let mut c = Cursor::new(want.as_ref());

        let s = AuthUnixParams::from_cursor(&mut c, 24).expect("deserialise failed");

        assert_eq!(s.stamp(), 0);
        assert_eq!(s.machine_name_str(), "");
        assert_eq!(s.uid(), 0);
        assert_eq!(s.gid(), 0);
        assert_eq!(s.gids(), Some(&smallvec![0]));
        assert_eq!(s.serialised_len(), 24);

        let mut buf = Cursor::new(Vec::new());
        s.serialise_into(&mut buf).expect("failed to serialise");

        let buf = buf.into_inner();
        assert_eq!(want.len(), buf.len());
        assert_eq!(want.as_ref(), buf.as_slice());
    }

    #[test]
    fn test_deserialise_bytes() {
        #[rustfmt::skip]
        // Known good wire value trimmed of flavor + length bytes.
        //
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
        //
        let want = hex!(
            "0000000000000000000001f50000001400000010000001f50000000c0000001400
            00003d0000004f000000500000005100000062000002bd000000210000006400000
            0cc000000fa0000018b0000018e0000018f"
        );
        let static_want: &'static [u8] = Box::leak(Box::new(want));

        let got =
            AuthUnixParams::try_from(Bytes::from(static_want)).expect("failed to deserialise");

        assert_eq!(got.stamp(), 0);
        assert_eq!(got.machine_name_str(), "");
        assert_eq!(got.uid(), 501);
        assert_eq!(got.gid(), 20);
        assert_eq!(
            got.gids(),
            Some(&smallvec![
                501, 12, 20, 61, 79, 80, 81, 98, 701, 33, 100, 204, 250, 395, 398, 399
            ])
        );
        assert_eq!(got.serialised_len(), 84);
    }

    #[test]
    fn test_empty_bytes() {
        // Known good wire value trimmed of flavor + length bytes.
        //
        // Credentials
        //     Flavor: AUTH_UNIX (1)
        //     Length: 24
        //     Stamp: 0x00000000
        //     Machine Name: <EMPTY>
        //         length: 0
        //         contents: <EMPTY>
        //     UID: 0
        //     GID: 0
        //     Auxiliary GIDs (1) [0]
        //         GID: 0
        let want = hex!("000000000000000000000000000000000000000100000000");
        let static_want: &'static [u8] = Box::leak(Box::new(want));

        let s = AuthUnixParams::try_from(Bytes::from(static_want)).expect("deserialise failed");

        assert_eq!(s.stamp(), 0);
        assert_eq!(s.machine_name_str(), "");
        assert_eq!(s.uid(), 0);
        assert_eq!(s.gid(), 0);
        assert_eq!(s.gids(), Some(&smallvec![0]));
        assert_eq!(s.serialised_len(), 24);

        let mut buf = Cursor::new(Vec::new());
        s.serialise_into(&mut buf).expect("failed to serialise");

        let buf = buf.into_inner();
        assert_eq!(want.len(), buf.len());
        assert_eq!(want.as_ref(), buf.as_slice());
    }
}
