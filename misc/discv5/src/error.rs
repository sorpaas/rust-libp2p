#[derive(Debug)]
pub enum Discv5Error {
    UnknownPublicKey,
    KeyTypeNotSupported(&'static str),
    KeyDerivationFailed,
    InvalidRemotePublicKey,
    InvalidSecretKey,
    EncryptionFail(String),
    DecryptionFail(String),
    Custom(String),
}
