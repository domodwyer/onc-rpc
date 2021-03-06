use crate::bytes_ext::BytesReaderExt;
use crate::Error;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use bytes::Bytes;
use std::{
    convert::TryFrom,
    io::{Cursor, Write},
};

const REJECTED_RPC_MISMATCH: u32 = 0;
const REJECTED_AUTH_ERROR: u32 = 1;

const AUTH_ERROR_SUCCESS: u32 = 0;
const AUTH_ERROR_BADCRED: u32 = 1;
const AUTH_ERROR_REJECTEDCRED: u32 = 2;
const AUTH_ERROR_BADVERF: u32 = 3;
const AUTH_ERROR_REJECTEDVERF: u32 = 4;
const AUTH_ERROR_TOOWEAK: u32 = 5;
const AUTH_ERROR_INVALIDRESP: u32 = 6;
const AUTH_ERROR_FAILED: u32 = 7;

/// The response type for a rejected RPC invocation.
#[derive(Debug, PartialEq)]
pub enum RejectedReply {
    /// The RPC version was not serviceable.
    ///
    /// Only RPC version 2 is supported.
    RpcVersionMismatch {
        /// The lowest supported version.
        low: u32,
        /// The highest supported version.
        high: u32,
    },

    /// The authentication credentials included in the request (if any) were
    /// rejected.
    AuthError(AuthError),
}

impl RejectedReply {
    /// Constructs a new `RejectedReply` by parsing the wire format read from
    /// `r`.
    ///
    /// `from_cursor` advances the position of `r` to the end of the
    /// `RejectedReply` structure.
    pub(crate) fn from_cursor(r: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let reply = match r.read_u32::<BigEndian>()? {
            REJECTED_RPC_MISMATCH => RejectedReply::RpcVersionMismatch {
                low: r.read_u32::<BigEndian>()?,
                high: r.read_u32::<BigEndian>()?,
            },
            REJECTED_AUTH_ERROR => RejectedReply::AuthError(AuthError::from_cursor(r)?),
            v => return Err(Error::InvalidRejectedReplyType(v)),
        };

        Ok(reply)
    }

    /// Serialises this `RejectedReply` into `buf`, advancing the cursor
    /// position by [`serialised_len`](RejectedReply::serialised_len) bytes.
    pub fn serialise_into<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        match self {
            RejectedReply::RpcVersionMismatch { low: l, high: h } => {
                buf.write_u32::<BigEndian>(REJECTED_RPC_MISMATCH)?;
                buf.write_u32::<BigEndian>(*l)?;
                buf.write_u32::<BigEndian>(*h)
            }
            RejectedReply::AuthError(err) => {
                buf.write_u32::<BigEndian>(REJECTED_AUTH_ERROR)?;
                err.serialise_into(buf)
            }
        }
    }

    /// Returns the on-wire length of this reply body once serialised.
    pub fn serialised_len(&self) -> u32 {
        let mut len = 0;

        // Discriminator
        len += 4;

        // Variant length
        len += match self {
            RejectedReply::RpcVersionMismatch {
                low: _low,
                high: _high,
            } => {
                // low, high
                4 + 4
            }
            RejectedReply::AuthError(e) => e.serialised_len(),
        };

        len
    }
}

impl TryFrom<&[u8]> for RejectedReply {
    type Error = Error;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        let mut c = Cursor::new(v);
        RejectedReply::from_cursor(&mut c)
    }
}

impl TryFrom<Bytes> for RejectedReply {
    type Error = Error;

    fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
        let reply = match v.try_u32()? {
            REJECTED_RPC_MISMATCH => RejectedReply::RpcVersionMismatch {
                low: v.try_u32()?,
                high: v.try_u32()?,
            },
            REJECTED_AUTH_ERROR => RejectedReply::AuthError(AuthError::try_from(v)?),
            v => return Err(Error::InvalidRejectedReplyType(v)),
        };

        Ok(reply)
    }
}

/// `AuthError` describes the reason the request authentication credentials were
/// rejected.
#[derive(Debug, PartialEq)]
pub enum AuthError {
    /// This is `AUTH_OK` in the spec.
    Success,

    /// The credentials were rejected.
    ///
    /// This is `AUTH_BADCRED` in the spec.
    BadCredentials,

    /// The session has been invalidated.
    ///
    /// This typically occurs if using
    /// [`AUTH_SHORT`](crate::auth::AuthFlavor::AuthShort) and the opaque
    /// identifier has been revoked on the server side.
    ///
    /// This is `AUTH_REJECTEDCRED` in the spec.
    RejectedCredentials,

    /// The verifier was not acceptable.
    ///
    /// This is `AUTH_BADVERF` in the spec.
    BadVerifier,

    /// The verifier was rejected/expired.
    ///
    /// This is `AUTH_REJECTEDVERF` in the spec.
    RejectedVerifier,

    /// The authentication scheme was rejected for security reasons.
    ///
    /// This is `AUTH_TOOWEAK` in the spec.
    TooWeak,

    /// The response verifier is invalid.
    ///
    /// This is `AUTH_INVALIDRESP` in the spec.
    InvalidResponseVerifier,

    /// An unknown failure occured.
    ///
    /// This is `AUTH_FAILED` in the spec.
    Failed,
}

impl AuthError {
    pub(crate) fn from_cursor(r: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let reply = match r.read_u32::<BigEndian>()? {
            AUTH_ERROR_SUCCESS => AuthError::Success,
            AUTH_ERROR_BADCRED => AuthError::BadCredentials,
            AUTH_ERROR_REJECTEDCRED => AuthError::RejectedCredentials,
            AUTH_ERROR_BADVERF => AuthError::BadVerifier,
            AUTH_ERROR_REJECTEDVERF => AuthError::RejectedVerifier,
            AUTH_ERROR_TOOWEAK => AuthError::TooWeak,
            AUTH_ERROR_INVALIDRESP => AuthError::InvalidResponseVerifier,
            AUTH_ERROR_FAILED => AuthError::Failed,
            v => return Err(Error::InvalidAuthError(v)),
        };

        Ok(reply)
    }

    /// Serialises this `AuthError` into `buf`, advancing the cursor position by
    /// [`serialised_len`](AuthError::serialised_len) bytes.
    pub fn serialise_into<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        let id = match self {
            AuthError::Success => AUTH_ERROR_SUCCESS,
            AuthError::BadCredentials => AUTH_ERROR_BADCRED,
            AuthError::RejectedCredentials => AUTH_ERROR_REJECTEDCRED,
            AuthError::BadVerifier => AUTH_ERROR_BADVERF,
            AuthError::RejectedVerifier => AUTH_ERROR_REJECTEDVERF,
            AuthError::TooWeak => AUTH_ERROR_TOOWEAK,
            AuthError::InvalidResponseVerifier => AUTH_ERROR_INVALIDRESP,
            AuthError::Failed => AUTH_ERROR_FAILED,
        };

        buf.write_u32::<BigEndian>(id)
    }

    /// Returns the on-wire length of this reply body once serialised.
    pub fn serialised_len(&self) -> u32 {
        4
    }
}

impl TryFrom<Bytes> for AuthError {
    type Error = Error;

    fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
        let reply = match v.try_u32()? {
            AUTH_ERROR_SUCCESS => AuthError::Success,
            AUTH_ERROR_BADCRED => AuthError::BadCredentials,
            AUTH_ERROR_REJECTEDCRED => AuthError::RejectedCredentials,
            AUTH_ERROR_BADVERF => AuthError::BadVerifier,
            AUTH_ERROR_REJECTEDVERF => AuthError::RejectedVerifier,
            AUTH_ERROR_TOOWEAK => AuthError::TooWeak,
            AUTH_ERROR_INVALIDRESP => AuthError::InvalidResponseVerifier,
            AUTH_ERROR_FAILED => AuthError::Failed,
            v => return Err(Error::InvalidAuthError(v)),
        };

        Ok(reply)
    }
}
