///! A wrapper around the libp2p Keypair which performs ENR specific signing/verification.
use libp2p_core::identity::{self, Keypair, PublicKey};
use secp256k1::Signature;
use sha3::{Digest, Keccak256};
use std::error::Error;
use std::fmt;

#[derive(Clone)]
/// The libp2p `Keypair` wrapper for ENR-specific signing.
pub struct EnrKeypair {
    inner: Keypair,
}

impl From<Keypair> for EnrKeypair {
    fn from(key: Keypair) -> EnrKeypair {
        EnrKeypair { inner: key }
    }
}

impl EnrKeypair {
    /// Performs ENR-specific signing for the v4 identity scheme.
    // This can be modified as support for more keys are given.
    pub fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        match self.inner {
            Keypair::Ed25519(ref keypair) => Ok(keypair.sign(msg)),
            Keypair::Rsa(ref pair) => pair.sign(msg).map_err(|e| e.into()),
            Keypair::Secp256k1(ref pair) => {
                // take a keccak256 hash then sign.
                let hash = Keccak256::digest(msg);
                let der_sig = pair.secret().sign_hash(&hash)?;
                // convert to compact form
                Ok(Signature::from_der(&der_sig)
                    .map_err(|_| SigningError::new(String::from("Incorrect DER format")))?
                    .serialize_compact()
                    .to_vec())
            }
        }
    }

    pub fn public(&self) -> EnrPublicKey {
        EnrPublicKey {
            inner: self.inner.public(),
        }
    }
}

/// The libp2p `PublicKey` wrapper to allow for custom ENR signature verification.
#[derive(Clone, Debug)]
pub struct EnrPublicKey {
    inner: PublicKey,
}

impl From<PublicKey> for EnrPublicKey {
    fn from(key: PublicKey) -> EnrPublicKey {
        EnrPublicKey { inner: key }
    }
}

/// Generates the ENR public key strings related associated with each `Keypair` variant.
impl Into<String> for EnrPublicKey {
    fn into(self) -> String {
        match self.inner {
            PublicKey::Ed25519(_) => String::from("ed25519"),
            PublicKey::Rsa(_) => String::from("rsa"),
            PublicKey::Secp256k1(_) => String::from("secp256k1"),
        }
    }
}

impl EnrPublicKey {
    /// Verify a raw message, given a public key for the v4 identity scheme.
    pub fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        // take the keccak hash
        match &self.inner {
            PublicKey::Ed25519(pk) => pk.verify(&msg, sig),
            PublicKey::Rsa(pk) => pk.verify(&msg, sig),
            PublicKey::Secp256k1(pk) => {
                // convert a compact encoded signature to a 256 bit DER-encoded signature
                let msg = Keccak256::digest(msg);
                if let Ok(sig) = Signature::from_compact(sig).and_then(|s| Ok(s.serialize_der())) {
                    return pk.verify_hash(&msg, &sig);
                }
                false
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match &self.inner {
            PublicKey::Ed25519(pk) => pk.encode().to_vec(),
            PublicKey::Rsa(pk) => pk.encode_x509(),
            PublicKey::Secp256k1(pk) => pk.encode().to_vec(),
        }
    }

    // For compatible keys, encode in uncompressed form. Necessary for generating node-id
    pub fn encode_uncompressed(&self) -> Vec<u8> {
        match &self.inner {
            PublicKey::Ed25519(pk) => pk.encode().to_vec(),
            PublicKey::Rsa(pk) => pk.encode_x509(),
            // Note: The current libsecp256k1 library prefixes the uncompressed output with a byte
            // indicating the type of output. We ignore it here
            PublicKey::Secp256k1(pk) => pk.encode_uncompressed()[1..].to_vec(),
        }
    }
}

/// An error during signing of a message.
#[derive(Debug)]
pub struct SigningError {
    msg: String,
    source: Option<Box<dyn Error + Send + Sync>>,
}

/// An error during encoding of key material.
impl SigningError {
    pub(crate) fn new<S: ToString>(msg: S) -> Self {
        Self {
            msg: msg.to_string(),
            source: None,
        }
    }

    pub(crate) fn source(self, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            source: Some(Box::new(source)),
            ..self
        }
    }
}

impl From<identity::error::SigningError> for SigningError {
    fn from(e: identity::error::SigningError) -> Self {
        SigningError::new("Libp2p Signing Error").source(e)
    }
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key signing error: {}", self.msg)
    }
}

impl Error for SigningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|s| &**s as &dyn Error)
    }
}
