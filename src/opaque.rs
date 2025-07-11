use std::io::{Cursor, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::Error;

/// [`Opaque`] is a wrapper over an opaque / uninterpreted byte array.
///
/// See [RFC1014] section 3.12.
///
/// [RFC1014]: https://datatracker.ietf.org/doc/html/rfc1014#section-3.12
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Opaque<T> {
    body: T,
}

impl<T> Opaque<T>
where
    T: AsRef<[u8]>,
{
    /// Construct an [`Opaque`] from the provided user payload (NOT a wire
    /// payload that includes a length prefix).
    pub(crate) fn from_user_payload(body: T) -> Opaque<T> {
        Opaque { body }
    }

    /// Construct an [`Opaque`] from the provided serialised / wire payload
    /// (that includes a length prefix).
    ///
    /// Returns an error without allocating any memory if the payload length
    /// prefix in `c` exceeds `max_len`.
    pub(crate) fn from_wire<'a>(
        c: &mut Cursor<&'a [u8]>,
        max_len: usize,
    ) -> Result<Opaque<&'a [u8]>, Error> {
        let payload_len = c.read_u32::<BigEndian>()?;
        if payload_len as usize > max_len {
            return Err(Error::InvalidLength);
        }

        // Read exactly the number of bytes specified in the payload_len prefix.
        let data = *c.get_ref();
        let start = c.position() as usize;
        let end = start + payload_len as usize;

        // Validate the subslice is within the data buffer
        if end > data.len() {
            return Err(Error::InvalidLength);
        }

        let body = &data[start..end];

        // Discard the sliced buffer and the appropriate amount of padding.
        c.set_position(end as u64 + pad_length(payload_len) as u64);

        Ok(Opaque { body })
    }

    /// Return the inner payload.
    pub(crate) fn into_payload(self) -> T {
        self.body
    }

    /// Return the payload length without serialisation overhead.
    pub(crate) fn len(&self) -> usize {
        self.body.as_ref().len()
    }

    /// Serialise the [`Opaque`] into `buf`, including the length prefix bytes.
    pub(crate) fn serialise_into<W: Write>(&self, buf: &mut W) -> Result<(), std::io::Error> {
        // Write the length prefix.
        let len = self.len() as u32;
        buf.write_u32::<BigEndian>(len)?;

        // Write the actual payload.
        buf.write_all(self.body.as_ref())?;

        // Pad the opaque bytes to have a length that is a multiple of 4.
        //
        // https://datatracker.ietf.org/doc/html/rfc1014#section-3.9
        let fill_bytes = pad_length(len) as usize;
        const PADDING: [u8; 3] = [0; 3];
        if fill_bytes > 0 {
            buf.write_all(&PADDING[..fill_bytes])?;
        }

        Ok(())
    }

    /// Return the serialised length of `self`, inclusive of length prefix
    /// bytes.
    pub(crate) fn serialised_len(&self) -> u32 {
        let payload_len: u32 = self.as_ref().len() as u32;
        4 /* length prefix */ + payload_len + pad_length(payload_len)
    }
}

impl<T> AsRef<[u8]> for Opaque<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.body.as_ref()
    }
}

// https://datatracker.ietf.org/doc/html/rfc1014#section-4
// (5) Why must variable-length data be padded with zeros?
// It is desirable that the same data encode into the same thing on all
// machines, so that encoded data can be meaningfully compared or
// checksummed.  Forcing the padded bytes to be zero ensures this.
#[inline]
pub(crate) fn pad_length(l: u32) -> u32 {
    if l % 4 == 0 {
        return 0;
    }
    4 - (l % 4)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use hex_literal::hex;
    use proptest::prelude::*;

    use super::Opaque;

    #[test]
    fn test_one_padded_opaque() {
        // 1. deserialize
        let raw = hex!("0000000f4c4150544f502d315151425044474d00").as_slice();
        // opaque bytes from hex
        let payload: [u8; 15] = [76, 65, 80, 84, 79, 80, 45, 49, 81, 81, 66, 80, 68, 71, 77];
        let mut cursor = Cursor::new(raw);
        let data = Opaque::<&[u8]>::from_wire(&mut cursor, 100).unwrap();
        // 4 bytes + 15 bytes (payload) + 1 padding byte
        assert_eq!(raw.len(), 20);
        assert_eq!(data.as_ref().len(), 15);
        assert!(data
            .as_ref()
            .iter()
            .zip(payload.iter())
            .all(|(a, b)| a == b));
        let mydata = Vec::from(data.body);

        // 2. erialize
        let myopaque = Opaque { body: mydata };
        let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
        myopaque.serialise_into(&mut buf).unwrap();
        assert_eq!(buf.get_ref().len(), 20);
        // assert input == output
        assert!(buf.get_ref().iter().zip(raw.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_no_padded_opaque() {
        // 1. deserialize
        let raw = hex!("0000000c4c4150544f5151425044474d").as_slice();
        // opaque bytes from hex
        let payload: [u8; 12] = [76, 65, 80, 84, 79, 81, 81, 66, 80, 68, 71, 77];
        let mut cursor = Cursor::new(raw);
        let data = Opaque::<&[u8]>::from_wire(&mut cursor, 100).unwrap();
        // 4 bytes + 12 bytes (payload)
        assert_eq!(raw.len(), 16);
        assert_eq!(data.as_ref().len(), 12);
        assert!(data
            .as_ref()
            .iter()
            .zip(payload.iter())
            .all(|(a, b)| a == b));
        let mydata = Vec::from(data.body);

        // 2. serialize
        let myopaque = Opaque { body: mydata };
        let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
        myopaque.serialise_into(&mut buf).unwrap();
        assert_eq!(buf.get_ref().len(), 16);
        // assert input == output
        assert!(buf.get_ref().iter().zip(raw.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_max_bytes() {
        let payload: [u8; 12] = [255, 65, 80, 84, 79, 81, 81, 66, 80, 68, 71, 77];
        let mut cursor = Cursor::new(payload.as_slice());
        Opaque::<&[u8]>::from_wire(&mut cursor, 100).expect_err("should hit max size");
    }

    proptest! {
        #[test]
        fn prop_round_trip(
            data in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            // Serialise the fuzzed payload into "buf".
            let mut buf = Vec::new();
            Opaque::from_user_payload(data.clone()).serialise_into(&mut buf).unwrap();

            // Deserialise the payload.
            let mut c = Cursor::new(buf.as_slice());
            let got = Opaque::<&[u8]>::from_wire(&mut c, data.len() + 1).unwrap().into_payload();

            assert_eq!(data, got);
        }
    }
}
