use bytes::{Buf, Bytes};

use crate::{pad_length, Error};

/// An extension to the `bytes::Bytes` type, providing a non-panic alternative
/// to the `get_u32` method, and an array helper.
pub(crate) trait BytesReaderExt {
    type Sliced;

    fn try_u32(&mut self) -> Result<u32, Error>;
    fn try_array(&mut self, max: usize) -> Result<Self::Sliced, Error>;
}

impl BytesReaderExt for Bytes {
    type Sliced = Self;

    fn try_u32(&mut self) -> Result<u32, Error> {
        if self.remaining() < std::mem::size_of::<u32>() {
            return Err(Error::InvalidLength);
        }
        Ok(self.get_u32())
    }

    /// Try to read an opaque XDR array, prefixed by a length u32.
    fn try_array(&mut self, max: usize) -> Result<Self, Error> {
        let len = self.try_u32()? as usize;
        let padded_len = len + pad_length(len as u32) as usize;

        if self.remaining() < padded_len || padded_len > max {
            return Err(Error::InvalidLength);
        }

        if self.as_ref()[len..padded_len].iter().any(|e| *e != 0) {
            return Err(Error::InvalidPaddingData)
        }
        
        let data = self.slice(..len);
        self.advance(padded_len);

        Ok(data)
    }
}
