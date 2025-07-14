use thiserror::Error;

/// Error types returned by this crate.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq)]
pub enum Error {
    /// The message header indicates the RPC message is longer than the amount
    /// of data in the buffer, or the buffer contains more than one message.
    ///
    /// This error may also be returned if the RPC message parsed from the
    /// buffer is unexpectedly shorter than the header length indicates - in
    /// this case, `buffer_len` will be more than `expected` and may indicate a
    /// parsing error.
    #[error("incomplete rpc message (got {buffer_len} bytes, expected {expected})")]
    IncompleteMessage {
        /// The length of the buffer provided.
        buffer_len: usize,

        /// The length expected for this message type.
        expected: usize,
    },

    /// The buffer is too small to contain the RPC header.
    #[error("incomplete fragment header")]
    IncompleteHeader,

    /// The RPC message is fragmented and needs to be reassembled.
    ///
    /// This library doesn't currently support fragmented messages and this
    /// error will be returned when parsing any message with the "last fragment"
    /// bit unset in the header.
    #[error("RPC message is fragmented")]
    Fragmented,

    /// The message type in the RPC request is neither [`MessageType::Call`]
    /// or [`MessageType::Reply`].
    ///
    /// This is a violation of the spec.
    ///
    /// [`MessageType::Call`]: crate::MessageType::Call
    /// [`MessageType::Reply`]: crate::MessageType::Reply
    #[error("invalid rpc message type {0}")]
    InvalidMessageType(u32),

    /// The message type in the RPC request is neither [`ReplyBody::Accepted`]
    /// or [`ReplyBody::Denied`].
    ///
    /// This is a violation of the spec.
    ///
    /// [`ReplyBody::Accepted`]: crate::ReplyBody::Accepted
    /// [`ReplyBody::Denied`]: crate::ReplyBody::Denied
    #[error("invalid rpc reply type {0}")]
    InvalidReplyType(u32),

    /// The reply status code is not one of the specified [status
    /// codes](crate::AcceptedStatus).
    ///
    /// This is a violation of the spec.
    #[error("invalid rpc reply status {0}")]
    InvalidReplyStatus(u32),

    /// The auth or verifier is invalid or malformed.
    #[error("invalid rpc auth data")]
    InvalidAuthData,

    /// The auth error code is not one of the specified [error
    /// codes](crate::AuthError).
    ///
    /// This is a violation of the spec.
    #[error("invalid rpc auth error status {0}")]
    InvalidAuthError(u32),

    /// The rejected reply status code is not one of the specified [status
    /// codes](crate::RejectedReply).
    ///
    /// This is a violation of the spec.
    #[error("invalid rpc rejected reply type {0}")]
    InvalidRejectedReplyType(u32),

    /// A variable length type has a malformed length value which would exceed
    /// the length of the buffer.
    #[error("invalid length in rpc message")]
    InvalidLength,

    /// The message contains a rpc protocol identifier that is not 2.
    #[error("invalid rpc version {0}")]
    InvalidRpcVersion(u32),

    /// The [machine name](crate::auth::AuthUnixParams::machine_name) contains
    /// non-UTF8 characters.
    #[error("invalid machine name: {0}")]
    InvalidMachineName(#[from] std::str::Utf8Error),

    /// An I/O error occurred when trying to parse the buffer.
    #[error("i/o error ({0:?}): {1}")]
    IOError(std::io::ErrorKind, String),
}

impl From<std::io::Error> for Error {
    fn from(v: std::io::Error) -> Self {
        Self::IOError(v.kind(), v.to_string())
    }
}
