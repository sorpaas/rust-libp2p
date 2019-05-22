#[derive(Debug)]
pub enum Discv5Error {
    UnknownPublicKey,
    KeyTypeNotSupported(&'static str),
    KeyDerivationFailed,
    InvalidRemotePublicKey,
    InvalidSecretKey,
    InvalidSignature,
    EncryptionFail(String),
    DecryptionFail(String),
    Custom(&'static str),
}
