#[derive(Debug)]
pub enum Discv5Error {
    UnknownPublicKey,
    PublicKeyNotSupported(&'static str),
    KeyDerivationFailed,
}
