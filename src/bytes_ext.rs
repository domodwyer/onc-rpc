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
    fn try_array(&mut self, max_len: usize) -> Result<Self, Error> {
        let payload_len = self.try_u32()? as usize;
        if payload_len > max_len {
            return Err(Error::InvalidLength);
        }

        let end_plus_padding = payload_len + pad_length(payload_len as u32) as usize;

        // Validate the subslice is within the data buffer
        if end_plus_padding > self.len() {
            return Err(Error::InvalidLength);
        }

        let body = self.slice(..payload_len);
        self.advance(end_plus_padding);

        Ok(body)
    }
}
