use crate::auth::AuthFlavor;
use crate::bytes_ext::BytesReaderExt;
use crate::Error;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Buf, Bytes};
use std::convert::TryFrom;
use std::io::{Cursor, Write};

const REPLY_SUCCESS: u32 = 0;
const REPLY_PROG_UNAVAIL: u32 = 1;
const REPLY_PROG_MISMATCH: u32 = 2;
const REPLY_PROC_UNAVAIL: u32 = 3;
const REPLY_GARBAGE_ARGS: u32 = 4;
const REPLY_SYSTEM_ERR: u32 = 5;

/// A type sent in response to a request that contains credentials accepted by
/// the server.
#[derive(Debug, PartialEq)]
pub struct AcceptedReply<T, P>
where
    T: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    auth_verifier: AuthFlavor<T>,
    status: AcceptedStatus<P>,
}

impl<'a> AcceptedReply<&'a [u8], &'a [u8]> {
    /// Constructs a new `AcceptedReply` by parsing the wire format read from
    /// `r`.
    ///
    /// `from_cursor` advances the position of `r` to the end of the
    /// `AcceptedReply` structure.
    pub(crate) fn from_cursor(r: &mut Cursor<&'a [u8]>) -> Result<Self, Error> {
        Ok(AcceptedReply {
            auth_verifier: AuthFlavor::from_cursor(r)?,
            status: AcceptedStatus::from_cursor(r)?,
        })
    }
}

impl<T, P> AcceptedReply<T, P>
where
    T: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    /// Constructs a new `AcceptedReply` with the specified
    /// [`AcceptedStatus`](AcceptedStatus).
    pub fn new(auth_verifier: AuthFlavor<T>, status: AcceptedStatus<P>) -> Self {
        AcceptedReply {
            auth_verifier,
            status,
        }
    }

    /// Serialises this `AcceptedReply` into `buf`, advancing the cursor
    /// position by [`serialised_len`](AcceptedReply::serialised_len) bytes.
    pub fn serialise_into<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        self.auth_verifier.serialise_into(&mut buf)?;
        self.status.serialise_into(&mut buf)
    }

    /// Returns the on-wire length of this type once serialised.
    pub fn serialised_len(&self) -> u32 {
        self.auth_verifier.serialised_len() + self.status.serialised_len()
    }

    /// Returns the auth verifier for use by the client to validate the server.
    pub fn auth_verifier(&self) -> &AuthFlavor<T> {
        &self.auth_verifier
    }

    /// Returns the status code of the response.
    pub fn status(&self) -> &AcceptedStatus<P> {
        &self.status
    }
}

impl<'a> TryFrom<&'a [u8]> for AcceptedReply<&'a [u8], &'a [u8]> {
    type Error = Error;

    fn try_from(v: &'a [u8]) -> Result<Self, Self::Error> {
        let mut c = Cursor::new(v);
        AcceptedReply::from_cursor(&mut c)
    }
}

impl TryFrom<Bytes> for AcceptedReply<Bytes, Bytes> {
    type Error = Error;

    fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
        // Deserialise the auth flavor using a copy of v, and then advance the
        // pointer in v.
        let auth_verifier = AuthFlavor::try_from(v.clone())?;
        v.advance(auth_verifier.serialised_len() as usize);

        Ok(AcceptedReply {
            auth_verifier,
            status: AcceptedStatus::try_from(v)?,
        })
    }
}

/// The response status code for a request that contains valid credentials.
#[derive(Debug, PartialEq)]
pub enum AcceptedStatus<P>
where
    P: AsRef<[u8]>,
{
    /// The RPC was successful, and the response payload is contained in the
    /// variant.
    Success(P),

    /// The specified program identifier has no handler in this server.
    ///
    /// This is `PROG_UNAVAIL` in the spec.
    ProgramUnavailable,

    /// The program to invoke was found, but it doesn't support the requested
    /// version.
    ///
    /// This is `PROG_MISMATCH` in the spec.
    ProgramMismatch {
        /// The lowest supported program version.
        low: u32,

        /// The highest supported program version.
        high: u32,
    },

    /// The program to invoke was found, but the procedure number is not
    /// recognised.
    ///
    /// This is `PROC_UNAVAIL` in the spec.
    ProcedureUnavailable,

    /// The arguments provided to the RPC endpoint were not serialised
    /// correctly, or otherwise unacceptable.
    ///
    /// This is `GARBAGE_ARGS` in the spec.
    GarbageArgs,

    /// The server experienced an internal error.
    ///
    /// This is `SYSTEM_ERR` in the spec.
    SystemError,
}

impl<'a> AcceptedStatus<&'a [u8]> {
    /// Constructs a new `AcceptedStatus` by parsing the wire format read from
    /// `r`.
    ///
    /// `from_cursor` advances the position of `r` to the end of the
    /// `AcceptedStatus` structure.
    pub(crate) fn from_cursor(r: &mut Cursor<&'a [u8]>) -> Result<Self, Error> {
        // Read the RPC version and stop if it is not 2.
        let reply = match r.read_u32::<BigEndian>()? {
            REPLY_SUCCESS => AcceptedStatus::new_success(r),
            REPLY_PROG_UNAVAIL => AcceptedStatus::ProgramUnavailable,
            REPLY_PROG_MISMATCH => AcceptedStatus::ProgramMismatch {
                low: r.read_u32::<BigEndian>()?,
                high: r.read_u32::<BigEndian>()?,
            },
            REPLY_PROC_UNAVAIL => AcceptedStatus::ProcedureUnavailable,
            REPLY_GARBAGE_ARGS => AcceptedStatus::GarbageArgs,
            REPLY_SYSTEM_ERR => AcceptedStatus::SystemError,
            v => return Err(Error::InvalidReplyStatus(v)),
        };

        Ok(reply)
    }

    fn new_success(r: &mut Cursor<&'a [u8]>) -> Self {
        let data = *r.get_ref();
        let start = r.position() as usize;
        let payload = &data[start..];

        AcceptedStatus::Success(payload)
    }
}

impl<P> AcceptedStatus<P>
where
    P: AsRef<[u8]>,
{
    /// Serialises this `AcceptedStatus` into `buf`, advancing the cursor
    /// position by [`serialised_len`](AcceptedStatus::serialised_len) bytes.
    pub fn serialise_into<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        match self {
            AcceptedStatus::Success(p) => {
                buf.write_u32::<BigEndian>(REPLY_SUCCESS)?;
                buf.write_all(p.as_ref())
            }
            AcceptedStatus::ProgramUnavailable => buf.write_u32::<BigEndian>(REPLY_PROG_UNAVAIL),
            AcceptedStatus::ProgramMismatch { low: l, high: h } => {
                buf.write_u32::<BigEndian>(REPLY_PROG_MISMATCH)?;
                buf.write_u32::<BigEndian>(*l)?;
                buf.write_u32::<BigEndian>(*h)
            }
            AcceptedStatus::ProcedureUnavailable => buf.write_u32::<BigEndian>(REPLY_PROC_UNAVAIL),
            AcceptedStatus::GarbageArgs => buf.write_u32::<BigEndian>(REPLY_GARBAGE_ARGS),
            AcceptedStatus::SystemError => buf.write_u32::<BigEndian>(REPLY_SYSTEM_ERR),
        }
    }

    /// Returns the on-wire length of this type once serialised.
    pub fn serialised_len(&self) -> u32 {
        let mut len = 0;

        // Discriminator
        len += 4;

        // Variant length
        len += match self {
            AcceptedStatus::Success(p) => p.as_ref().len() as u32,
            AcceptedStatus::ProgramUnavailable => 0,
            AcceptedStatus::ProgramMismatch { low: _l, high: _h } => 8,
            AcceptedStatus::ProcedureUnavailable => 0,
            AcceptedStatus::GarbageArgs => 0,
            AcceptedStatus::SystemError => 0,
        };

        len
    }
}

impl<'a> TryFrom<&'a [u8]> for AcceptedStatus<&'a [u8]> {
    type Error = Error;

    fn try_from(v: &'a [u8]) -> Result<Self, Self::Error> {
        let mut c = Cursor::new(v);
        AcceptedStatus::from_cursor(&mut c)
    }
}

impl TryFrom<Bytes> for AcceptedStatus<Bytes> {
    type Error = Error;

    fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
        let reply = match v.try_u32()? {
            REPLY_SUCCESS => AcceptedStatus::Success(v),
            REPLY_PROG_UNAVAIL => AcceptedStatus::ProgramUnavailable,
            REPLY_PROG_MISMATCH => AcceptedStatus::ProgramMismatch {
                low: v.try_u32()?,
                high: v.try_u32()?,
            },
            REPLY_PROC_UNAVAIL => AcceptedStatus::ProcedureUnavailable,
            REPLY_GARBAGE_ARGS => AcceptedStatus::GarbageArgs,
            REPLY_SYSTEM_ERR => AcceptedStatus::SystemError,
            v => return Err(Error::InvalidReplyStatus(v)),
        };

        Ok(reply)
    }
}
