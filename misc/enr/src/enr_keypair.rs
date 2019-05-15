use libp2p_core::identity::error::SigningError;
///! A wrapper around the libp2p Keypair which performs ENR specific signing/verifcation.
use libp2p_core::identity::{Keypair, PublicKey};
use secp256k1::Signature;
use sha3::{Digest, Keccak256};

#[derive(Clone)]
pub struct EnrKeypair {
    inner: Keypair,
}

impl From<Keypair> for EnrKeypair {
    fn from(key: Keypair) -> EnrKeypair {
        EnrKeypair { inner: key }
    }
}

impl EnrKeypair {
    /// Perform ENR-specific signing.
    // This can be modified as support for more keys are given.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        match self.inner {
            Keypair::Ed25519(ref keypair) => Ok(keypair.sign(msg)),
            Keypair::Rsa(ref pair) => pair.sign(msg),
            Keypair::Secp256k1(ref pair) => {
                // take a keccak256 hash then sign.
                let hash = Keccak256::digest(msg);
                let der_sig = pair.secret().sign_hash(&hash)?;
                // convert to compact form
                Ok(Signature::from_der(&der_sig)
                    .map_err(|_| SigningError::from(String::from("Incorrect DER format")))?
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

/// Wraps a libp2p `PublicKey` to allow for custom ENR signature verification.
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
impl Into<String> for EnrKeypair {
    fn into(self) -> String {
        match self.inner {
            Keypair::Ed25519(_) => String::from("ed25519"),
            Keypair::Rsa(_) => String::from("rsa"),
            Keypair::Secp256k1(_) => String::from("secp256k1"),
        }
    }
}

impl EnrPublicKey {
    /// Verify a raw message, given a public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
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
            PublicKey::Secp256k1(pk) => pk.encode_uncompressed().to_vec(),
        }
    }
}
