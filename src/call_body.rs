use crate::auth::AuthFlavor;
use crate::Error;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::{Cursor, Write};

const RPC_VERSION: u32 = 2;

/// A request invoking an RPC.
///
/// This structure is the Rust equivilent of the `call_body` structure defined
/// in the [RFC](https://tools.ietf.org/html/rfc5531#section-9). The `rpcvers`
/// field (representing the RPC protocol version) is hard coded to `2`.
#[derive(Debug, PartialEq)]
pub struct CallBody<'a> {
    program: u32,
    program_version: u32,
    procedure: u32,

    auth_credentials: AuthFlavor<'a>,
    auth_verifier: AuthFlavor<'a>,

    payload: &'a [u8],
}

impl<'a> CallBody<'a> {
    /// Constructs a new `CallBody` by parsing the wire format read from `r`.
    ///
    /// `from_cursor` advances the position of `r` to the end of the `CallBody`
    /// structure.
    pub(crate) fn from_cursor(r: &mut Cursor<&'a [u8]>) -> Result<Self, Error> {
        // Read the RPC version and stop if it is not 2.
        let rpc_version = r.read_u32::<BigEndian>()?;
        if rpc_version != RPC_VERSION {
            return Err(Error::InvalidRpcVersion(rpc_version));
        }

        let program = r.read_u32::<BigEndian>()?;
        let program_version = r.read_u32::<BigEndian>()?;
        let procedure = r.read_u32::<BigEndian>()?;
        let auth_credentials = AuthFlavor::from_cursor(r)?;
        let auth_verifier = AuthFlavor::from_cursor(r)?;

        let data = *r.get_ref();
        let start = r.position() as usize;
        let payload = &data[start..];

        Ok(CallBody {
            program,
            program_version,
            procedure,
            auth_credentials,
            auth_verifier,
            payload,
        })
    }

    /// Construct a new RPC invocation request.
    pub fn new(
        program: u32,
        program_version: u32,
        procedure: u32,
        auth_credentials: AuthFlavor<'a>,
        auth_verifier: AuthFlavor<'a>,
        payload: &'a [u8],
    ) -> Self {
        CallBody {
            program,
            program_version,
            procedure,
            auth_credentials,
            auth_verifier,
            payload,
        }
    }

    /// Serialises this `CallBody` into `buf`, advancing the cursor position by
    /// [`serialised_len`](CallBody::serialised_len) bytes.
    pub fn serialise_into(&self, buf: &mut Cursor<Vec<u8>>) -> Result<(), std::io::Error> {
        buf.write_u32::<BigEndian>(RPC_VERSION)?;
        buf.write_u32::<BigEndian>(self.program)?;
        buf.write_u32::<BigEndian>(self.program_version)?;
        buf.write_u32::<BigEndian>(self.procedure)?;

        self.auth_credentials.serialise_into(buf)?;
        self.auth_verifier.serialise_into(buf)?;

        buf.write_all(self.payload)
    }

    /// Returns the on-wire length of this call body once serialised.
    pub fn serialised_len(&self) -> u32 {
        let mut l = std::mem::size_of::<u32>() * 4;

        l += self.auth_credentials.serialised_len() as usize;
        l += self.auth_verifier.serialised_len() as usize;
        l += self.payload.as_ref().len();

        l as u32
    }

    /// Returns the RPC version of this request.
    ///
    /// This crate supports the ONC RPC version 2 only.
    pub fn rpc_version(&self) -> u32 {
        2
    }

    /// Returns the program identifier in this request.
    pub fn program(&self) -> u32 {
        self.program
    }

    /// The version of the program to be invoked.
    pub fn program_version(&self) -> u32 {
        self.program_version
    }

    /// The program procedure number identifying the RPC to invoke.
    pub fn procedure(&self) -> u32 {
        self.procedure
    }

    /// The credentials to use for authenticating the request.
    pub fn auth_credentials(&self) -> &AuthFlavor<'a> {
        &self.auth_credentials
    }

    /// The verifier that should be used to validate the authentication
    /// credentials.
    ///
    /// The RFC says the following about the verifier:
    /// ```text
    /// The purpose of the authentication verifier is to validate the
    /// authentication credential.  Note that these two items are
    /// historically separate, but are always used together as one logical
    /// entity.
    /// ```
    pub fn auth_verifier(&self) -> &AuthFlavor<'a> {
        &self.auth_verifier
    }

    /// Returns a reference to the opaque message payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
}

impl<'a> TryFrom<&'a [u8]> for CallBody<'a> {
    type Error = Error;

    fn try_from(v: &'a [u8]) -> Result<Self, Self::Error> {
        let mut c = Cursor::new(v);
        CallBody::from_cursor(&mut c)
    }
}
