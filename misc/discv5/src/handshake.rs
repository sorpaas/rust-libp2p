///! Implementation for generating session keys in the Discv5 protocol.
///! Currently, Diffie-Hellman key agreement is performed with known public key types. Session keys
///! are then derived using the HKDF (SHA2-256) key derivation function.
use crate::error::Discv5Error;
use crate::packet::{Nonce, NODE_ID_LENGTH};
use enr::Enr;
use hkdf::Hkdf;
use lazy_static::lazy_static;
use libp2p_core::PublicKey;
use sha2::Sha256;

const INFO_LENGTH: usize = 26 + 2 * NODE_ID_LENGTH;

// Cached `Secp256k1` context, to avoid recreating it every time.
lazy_static! {
    static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// Generates session and auth-response keys for a nonce and remote ENR. This currently only
/// supports Secp256k1 signed ENR's.
pub fn generate(
    local_enr: &Enr,
    remote_enr: &Enr,
    id_nonce: &Nonce,
) -> Result<([u8; 16], [u8; 16], [u8; 16], PublicKey), Discv5Error> {
    // verify we know the public key and it's type
    let pubkey = remote_enr
        .pubkey()
        .ok_or_else(|| Discv5Error::UnknownPublicKey)?;

    let (secret, ephem_pk) = match &pubkey {
        PublicKey::Rsa(_) => {
            // don't support ephemeral RSA keys yet
            return Err(Discv5Error::PublicKeyNotSupported("RSA"));
        }
        PublicKey::Ed25519(_) => {
            // TODO: Convert the node's ed25519 public key (which is encoded as a
            // curve25519_dalek::curve::CompressedEdwardsY to a montgomery point such
            // that it can be read as x25519 public key to perform Diffie Hellman.

            return Err(Discv5Error::PublicKeyNotSupported("Ed25519"));
        }

        PublicKey::Secp256k1(pubkey) => {
            let remote_pk = secp256k1::key::PublicKey::from_slice(&pubkey.encode())
                .map_err(|_| Discv5Error::UnknownPublicKey)?;

            let ephem_sk = secp256k1::key::SecretKey::new(&mut secp256k1::rand::thread_rng());
            let ephem_pk = secp256k1::key::PublicKey::from_secret_key(&SECP, &ephem_sk);

            let secret = secp256k1::ecdh::SharedSecret::new(&remote_pk, &ephem_sk);

            // convert to a libp2p public key
            // TODO: It may be more sensible to leave as a raw encoded public key
            let libp2p_pk =
                libp2p_core::identity::secp256k1::PublicKey::decode(&ephem_pk.serialize())
                    .expect("Valid public key");
            let ephem_pk = PublicKey::Secp256k1(libp2p_pk);

            (secret, ephem_pk)
        }
    };

    let mut info = [0u8; INFO_LENGTH];
    info[0..26].copy_from_slice(b"discovery v5 key agreement");
    info[26..NODE_ID_LENGTH].copy_from_slice(&local_enr.node_id());
    info[26 + NODE_ID_LENGTH..].copy_from_slice(&remote_enr.node_id());

    let hk = Hkdf::<Sha256>::extract(Some(&secret[..]), id_nonce);

    let mut okm = [0u8; 48];
    hk.expand(&info, &mut okm)
        .map_err(|_| Discv5Error::KeyDerivationFailed)?;

    let mut initiator_key = [0u8; 16];
    let mut responder_key = [0u8; 16];
    let mut auth_resp_key = [0u8; 16];
    initiator_key.copy_from_slice(&okm[0..16]);
    responder_key.copy_from_slice(&okm[16..32]);
    auth_resp_key.copy_from_slice(&okm[32..48]);
    Ok((initiator_key, responder_key, auth_resp_key, ephem_pk))
}
