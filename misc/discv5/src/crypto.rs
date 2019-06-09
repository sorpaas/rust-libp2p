///! Implementation for generating session keys in the Discv5 protocol.
///! Currently, Diffie-Hellman key agreement is performed with known public key types. Session keys
///! are then derived using the HKDF (SHA2-256) key derivation function.
///
/// There is no abstraction in this module as the specification explicitly defines a singular
/// encryption and key-derivation algorithms. Future versions may abstract some of these to allow
/// for different algorithms.
use crate::error::Discv5Error;
use crate::packet::{AuthHeader, AuthResponse, AuthTag, NodeId, Nonce, Tag, NODE_ID_LENGTH};
use enr::Enr;
use hkdf::Hkdf;
use lazy_static::lazy_static;
use libp2p_core::{identity::Keypair, PublicKey};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use rand::RngCore;
use sha2::Sha256;

const INFO_LENGTH: usize = 26 + 2 * NODE_ID_LENGTH;
const KEY_LENGTH: usize = 16;
const KEY_AGREEMENT_STRING: &'static str = "discovery v5 key agreement";

type Key = [u8; KEY_LENGTH];

// Cached `Secp256k1` context, to avoid recreating it every time.
lazy_static! {
    static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// Generates session and auth-response keys for a nonce and remote ENR. This currently only
/// supports Secp256k1 signed ENR's.
pub fn generate_session_keys(
    local_id: &NodeId,
    remote_enr: &Enr,
    id_nonce: &Nonce,
) -> Result<(Key, Key, Key, Vec<u8>), Discv5Error> {
    // verify we know the public key and it's type
    let pubkey = remote_enr.public_key();

    let (secret, ephem_pk) = match &pubkey {
        PublicKey::Rsa(_) => {
            // don't support ephemeral RSA keys yet
            return Err(Discv5Error::KeyTypeNotSupported("RSA"));
        }
        PublicKey::Ed25519(_) => {
            // TODO: Convert the node's ed25519 public key (which is encoded as a
            // curve25519_dalek::curve::CompressedEdwardsY to a montgomery point such
            // that it can be read as x25519 public key to perform Diffie Hellman.

            return Err(Discv5Error::KeyTypeNotSupported("Ed25519"));
        }

        PublicKey::Secp256k1(pubkey) => {
            let remote_pk = secp256k1::key::PublicKey::from_slice(&pubkey.encode())
                .map_err(|_| Discv5Error::UnknownPublicKey)?;

            let ephem_sk = {
                let mut r = rand::thread_rng();
                let mut b = [0; secp256k1::constants::SECRET_KEY_SIZE];
                loop {
                    // until a value is given within the curve order
                    r.fill_bytes(&mut b);
                    if let Ok(k) = secp256k1::SecretKey::from_slice(&b) {
                        break k;
                    }
                }
            };

            let secp = secp256k1::Secp256k1::new();
            let ephem_pk = secp256k1::PublicKey::from_secret_key(&secp, &ephem_sk);
            let secret = secp256k1::ecdh::SharedSecret::new(&remote_pk, &ephem_sk);

            // store as uncompressed
            let ephem_pk = ephem_pk.serialize().to_vec();

            (secret, ephem_pk)
        }
    };

    let (initiator_key, responder_key, auth_resp_key) =
        derive_key(&secret[..], local_id, &remote_enr.node_id, id_nonce)?;

    Ok((initiator_key, responder_key, auth_resp_key, ephem_pk))
}

#[inline]
fn derive_key(
    secret: &[u8],
    first_id: &NodeId,
    second_id: &NodeId,
    id_nonce: &Nonce,
) -> Result<(Key, Key, Key), Discv5Error> {
    let mut info = [0u8; INFO_LENGTH];
    info[0..26].copy_from_slice(KEY_AGREEMENT_STRING.as_bytes());
    info[26..26 + NODE_ID_LENGTH].copy_from_slice(first_id);
    info[26 + NODE_ID_LENGTH..].copy_from_slice(second_id);

    let hk = Hkdf::<Sha256>::extract(Some(secret), id_nonce);

    let mut okm = [0u8; 3 * KEY_LENGTH];
    hk.expand(&info, &mut okm)
        .map_err(|_| Discv5Error::KeyDerivationFailed)?;

    let mut initiator_key: Key = Default::default();
    let mut responder_key: Key = Default::default();
    let mut auth_resp_key: Key = Default::default();
    initiator_key.copy_from_slice(&okm[0..KEY_LENGTH]);
    responder_key.copy_from_slice(&okm[KEY_LENGTH..2 * KEY_LENGTH]);
    auth_resp_key.copy_from_slice(&okm[2 * KEY_LENGTH..3 * KEY_LENGTH]);

    Ok((initiator_key, responder_key, auth_resp_key))
}

/// Derives the session keys for a public key type that matches the local keypair.
pub fn derive_keys_from_pubkey(
    local_keypair: &Keypair,
    local_id: &NodeId,
    remote_id: &NodeId,
    id_nonce: &Nonce,
    ephem_pubkey: &[u8],
) -> Result<(Key, Key, Key), Discv5Error> {
    let secret = match local_keypair {
        Keypair::Rsa(_) => {
            // don't support RSA keys yet
            return Err(Discv5Error::KeyTypeNotSupported("RSA"));
        }
        Keypair::Ed25519(_) => {
            // don't support RSA keys yet
            return Err(Discv5Error::KeyTypeNotSupported("Ed25519"));
        }
        Keypair::Secp256k1(key) => {
            // convert remote pubkey into secp256k1 public key
            // the key type should match our own node record
            let remote_pubkey = secp256k1::key::PublicKey::from_slice(ephem_pubkey)
                .map_err(|_| Discv5Error::InvalidRemotePublicKey)?;

            // convert our secret key into a secp256k1 secret key
            let sk = secp256k1::key::SecretKey::from_slice(&key.secret().to_bytes())
                .map_err(|_| Discv5Error::InvalidSecretKey)?;

            let secret = secp256k1::ecdh::SharedSecret::new(&remote_pubkey, &sk);
            secret[..].to_vec()
        }
    };

    derive_key(&secret, remote_id, local_id, id_nonce)
}

/// Verifies the encoding and nonce signature given in the authentication header. If
/// the header contains an updated ENR, it is returned.
#[inline]
pub fn verify_authentication_header(
    auth_resp_key: &Key,
    generated_nonce: &[u8],
    header: &AuthHeader,
    tag: &Tag,
    remote_public_key: &PublicKey,
) -> Result<Option<Enr>, Discv5Error> {
    if header.auth_scheme_name != "gsm" {
        return Err(Discv5Error::Custom("Invalid authentication scheme".into()));
    }

    // decrypt the auth-response
    let rlp_auth_response = decrypt_message(auth_resp_key, [0u8; 12], &header.auth_response, tag)?;
    let auth_response = rlp::decode::<AuthResponse>(&rlp_auth_response)
        .map_err(|_| Discv5Error::Custom("Invalid auth response format"))?;

    // verify the nonce signature
    if !remote_public_key.verify(&generated_nonce, &auth_response.signature) {
        return Err(Discv5Error::InvalidSignature);
    }

    Ok(auth_response.updated_enr)
}

/// Decrypt messages that are post-fixed with an authenticated MAC.
pub fn decrypt_message(
    key: &Key,
    nonce: AuthTag,
    message: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Discv5Error> {
    if message.len() < 16 {
        return Err(Discv5Error::DecryptionFail(
            "Message not long enough to contain a MAC".into(),
        ));
    }

    let mut mac: [u8; 16] = Default::default();
    mac.copy_from_slice(&message[message.len() - 16..]);

    decrypt_aead(
        Cipher::aes_128_gcm(),
        key,
        Some(&nonce),
        aad,
        &message[..message.len() - 16],
        &mac,
    )
    .map_err(|e| Discv5Error::DecryptionFail(format!("Could not decrypt message. Error: {:?}", e)))
}

pub fn encrypt_with_header(
    auth_resp_key: &Key,
    encryption_key: &Key,
    auth_pt: &[u8],
    message: &[u8],
    ephem_pubkey: &[u8],
    tag: &Tag,
) -> Result<(AuthHeader, Vec<u8>), Discv5Error> {
    let ciphertext = encrypt_message(auth_resp_key, [0u8; 12], auth_pt, tag)?;

    // get the rlp_encoded auth_header
    let auth_tag: [u8; 12] = rand::random();
    let auth_header = AuthHeader::new(auth_tag, ephem_pubkey.to_vec(), Box::new(ciphertext));

    let mut auth_data = tag.to_vec();
    auth_data.append(&mut auth_header.encode());

    let ciphertext = encrypt_message(encryption_key, auth_tag, message, &auth_data)?;

    Ok((auth_header, ciphertext))
}

pub fn encrypt_message(
    key: &Key,
    nonce: AuthTag,
    message: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Discv5Error> {
    //let auth_tag: [u8; 12] = rand::random();
    let mut mac: [u8; 16] = Default::default();
    let mut msg_cipher = encrypt_aead(
        Cipher::aes_128_gcm(),
        key,
        Some(&nonce),
        aad,
        message,
        &mut mac,
    )
    .map_err(|e| Discv5Error::EncryptionFail(format!("{:?}", e)))?;

    // concat the ciphertext with the MAC
    msg_cipher.append(&mut mac.to_vec());
    Ok(msg_cipher)
}

#[cfg(test)]
mod tests {

    use super::*;
    use enr::EnrBuilder;
    use libp2p_core::identity::Keypair;
    use rand;

    #[test]
    fn derive_symmetric_keys() {
        let node1_kp = Keypair::generate_secp256k1();
        let node2_kp = Keypair::generate_secp256k1();

        let node1_enr = EnrBuilder::new().build(&node1_kp).unwrap();
        let node2_enr = EnrBuilder::new().build(&node2_kp).unwrap();

        let nonce: Nonce = rand::random();

        let (key1, key2, key3, pk) =
            generate_session_keys(&node1_enr.node_id, &node2_enr, &nonce).unwrap();
        let (key4, key5, key6) = derive_keys_from_pubkey(
            &node2_kp,
            &node2_enr.node_id,
            &node1_enr.node_id,
            &nonce,
            &pk,
        )
        .unwrap();

        assert_eq!(key1, key4);
        assert_eq!(key2, key5);
        assert_eq!(key3, key6);
    }

    #[test]
    fn encrypt_decrypt() {
        let tag: Tag = rand::random();
        let msg: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let key: Key = rand::random();
        let nonce: AuthTag = rand::random();

        let cipher = encrypt_message(&key, nonce, &msg, &tag).unwrap();

        let plain_text = decrypt_message(&key, nonce, &cipher, &tag).unwrap();

        assert_eq!(plain_text, msg);
    }

}
