/// Errors produced while building or validating protocol objects.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("invalid public key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("envelope is not addressed to this identity")]
    WrongRecipient,
    #[error("message too large ({0} bytes)")]
    TooLarge(usize),
    #[error("non-contributory Diffie-Hellman result")]
    WeakKey,
    #[error("the peer has not published prekeys")]
    MissingPrekeys,
    #[error("the session cannot send until the peer's first message arrives")]
    SessionNotReady,
    #[error("message is too far ahead of the ones received so far")]
    TooManySkipped,
}
