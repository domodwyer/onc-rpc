use std::io::{Cursor, Write};

use byteorder::{BigEndian, ReadBytesExt};

use crate::Error;

// Opaque is a Variable-length Array that holds an uninterpreted byte array
//https://datatracker.ietf.org/doc/html/rfc1014#section-3.12
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Opaque<T>
where
    T: AsRef<[u8]>,
{
    body: T,
}

impl<'a> TryFrom<&mut Cursor<&'a [u8]>> for Opaque<&'a [u8]> {
    type Error = Error;

    /// Deserialises a new [`Opaque`] from `cursor`.
    fn try_from(c: &mut Cursor<&'a [u8]>) -> Result<Opaque<&'a [u8]>, Self::Error> {
        let len = c.read_u32::<BigEndian>()?;
        let data = *c.get_ref();
        let start = c.position() as usize;
        let end = start + len as usize;
        let padded_end = pad_length(len) + end as u32;

        c.set_position(padded_end as u64);
        Ok(Opaque {
            body: &data[start..end],
        })
    }
}

/// read bytes from `r`
/// assuming the length header has already been consumed.
/// advances `r` with padded length
pub(crate) fn read_opaque<'a>(r: &mut Cursor<&'a [u8]>, expected_len: u32) -> Result<&'a [u8], Error>{
    let start_pos = r.position() as usize;
    let end_pos = start_pos + expected_len as usize;
    let data = *r.get_ref();
    let padded_end = pad_length(expected_len) + end_pos as u32;
    
    let total_len = r.get_ref().len();

    // If there is not enough data to advances, this function failed
    if total_len < padded_end as usize {
        return Err(Error::InvalidAuthData);
    }
    
    r.set_position(padded_end as u64);
    Ok(&data[start_pos..end_pos])
}

impl<T> Opaque<T>
where
    T: AsRef<[u8]> + Sized,
{
    pub(crate) fn from(data: T) -> Opaque<T> {
        Opaque {
            body: data,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.body.as_ref().len()
    }
    pub(crate) fn serialise_into<W: Write>(&self, buf: &mut W) -> Result<(), std::io::Error> {
            let len = self.as_ref().len() as u32;
            let _ = buf.write_all(self.as_ref());
            let fill_bytes = pad_length(len) as usize;
            const PADDING: [u8; 3] = [0; 3];
            if fill_bytes > 0 {
                buf.write_all(&PADDING[..fill_bytes])?;
            }
            Ok(())
    }
    pub(crate) fn serialised_len(&self) -> u32 {
        let len = self.as_ref().len() as u32;
        len + pad_length(len)
    }
}

impl<T> AsRef<[u8]> for Opaque<T>
where
    T: AsRef<[u8]> + Sized,
{
    fn as_ref(&self) -> &[u8] {
        self.body.as_ref()
    }
}

pub(crate) trait SerializeOpaque {
    fn serialise_into<W: Write>(&self, buf: &mut W) -> Result<(), std::io::Error>;

    fn serialised_len(&self) -> u32;
}

impl<T> SerializeOpaque for T
where T: AsRef<[u8]>
{
    fn serialise_into<W: Write>(&self, buf: &mut W) -> Result<(), std::io::Error> {
            let len = self.as_ref().len() as u32;
            let _ = buf.write_all(self.as_ref());
            let fill_bytes = pad_length(len) as usize;
            const PADDING: [u8; 3] = [0; 3];
            if fill_bytes > 0 {
                buf.write_all(&PADDING[..fill_bytes])?;
            }
            Ok(())
    }
    fn serialised_len(&self) -> u32 {
        let len = self.as_ref().len() as u32;
        len + pad_length(len)
    }
}

// impl<'a, T> SerializeOpaque for Opaque<'a, T>
// where
//     T: AsRef<[u8]> + Sized,
// {
//     /// Serialises this `Opaque` into `buf`, advancing the cursor position by
//     /// [`Opaque::serialised_len()`] bytes.
//     fn serialise_into<W: Write>(&self, buf: &mut W) -> Result<(), std::io::Error> {
//         let len = self.body.as_ref().len() as u32;
//         buf.write_u32::<BigEndian>(len)?;

//         let _ = buf.write_all(self.body.as_ref());
//         let fill_bytes = pad_length(len);
//         if fill_bytes > 0 {
//             buf.write_all(vec![0_u8; fill_bytes as usize].as_slice())?;
//         }
//         Ok(())
//     }

//     /// Returns the on-wire length of this opaque data once serialised.
//     fn serialised_len(&self) -> u32 {
//         let len = self.body.as_ref().len() as u32;
//         len + pad_length(len)
//     }
// }

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

    use byteorder::{BigEndian, WriteBytesExt};
    use hex_literal::hex;

    use super::Opaque;

    #[test]
    fn test_one_padded_opaque() {
        // 1. deserialize
        let raw = hex!("0000000f4c4150544f502d315151425044474d00").as_slice();
        // opaque bytes from hex
        let payload: [u8; 15] = [76, 65, 80, 84, 79, 80, 45, 49, 81, 81, 66, 80, 68, 71, 77];
        let mut cursor = Cursor::new(raw);
        let data = Opaque::try_from(&mut cursor).unwrap();
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
        let myopaque = Opaque {
            body: mydata,
        };
        let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
        buf.write_u32::<BigEndian>(myopaque.len() as u32).unwrap();
        let _ = myopaque.serialise_into(&mut buf);
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
        let data = Opaque::try_from(&mut cursor).unwrap();
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
        let myopaque = Opaque {
            body: mydata,
        };
        let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
        buf.write_u32::<BigEndian>(myopaque.len() as u32).unwrap();
        let _ = myopaque.serialise_into(&mut buf);
        assert_eq!(buf.get_ref().len(), 16);
        // assert input == output
        assert!(buf.get_ref().iter().zip(raw.iter()).all(|(a, b)| a == b));
    }
}
