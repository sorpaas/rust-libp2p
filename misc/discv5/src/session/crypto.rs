///! Implementation for generating session keys in the Discv5 protocol.
///! Currently, Diffie-Hellman key agreement is performed with known public key types. Session keys
///! are then derived using the HKDF (SHA2-256) key derivation function.
///
/// There is no abstraction in this module as the specification explicitly defines a singular
/// encryption and key-derivation algorithms. Future versions may abstract some of these to allow
/// for different algorithms.
use crate::error::Discv5Error;
use crate::packet::{AuthHeader, AuthResponse, AuthTag, Nonce, Tag};
use enr::{Enr, NodeId};
use hkdf::Hkdf;
use libp2p_core::{identity::Keypair, PublicKey};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use sha2::Sha256;
use secp256k1::Signature;

const NODE_ID_LENGTH: usize = 32;
const INFO_LENGTH: usize = 26 + 2 * NODE_ID_LENGTH;
const KEY_LENGTH: usize = 16;
const KEY_AGREEMENT_STRING: &str = "discovery v5 key agreement";
const KNOWN_SCHEME: &str = "gcm";
const NONCE_PREFIX: &str = "discovery-id-nonce";

type Key = [u8; KEY_LENGTH];

/* Session key generation */

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
            let remote_pk = secp256k1::PublicKey::parse(&pubkey.encode_uncompressed()).expect("is a valid key");

            let ephem_libp2p_sk = libp2p_core::identity::secp256k1::SecretKey::generate(); 
            let ephem_sk = secp256k1::SecretKey::parse(&ephem_libp2p_sk.to_bytes()).expect("valid key");
            let ephem_pk = secp256k1::PublicKey::from_secret_key(&ephem_sk);

            let secret = secp256k1::SharedSecret::new(&remote_pk, &ephem_sk).map_err(|_| Discv5Error::KeyDerivationFailed)?;
            // store as uncompressed
            let ephem_pk = ephem_pk.serialize().to_vec();

            (secret, ephem_pk)
        }
    };

    let (initiator_key, responder_key, auth_resp_key) =
        derive_key(secret.as_ref(), local_id, remote_enr.node_id(), id_nonce)?;

    Ok((initiator_key, responder_key, auth_resp_key, ephem_pk))
}

fn derive_key(
    secret: &[u8],
    first_id: &NodeId,
    second_id: &NodeId,
    id_nonce: &Nonce,
) -> Result<(Key, Key, Key), Discv5Error> {
    let mut info = [0u8; INFO_LENGTH];
    info[0..26].copy_from_slice(KEY_AGREEMENT_STRING.as_bytes());
    info[26..26 + NODE_ID_LENGTH].copy_from_slice(&first_id.raw());
    info[26 + NODE_ID_LENGTH..].copy_from_slice(&second_id.raw());

    let hk = Hkdf::<Sha256>::new(Some(id_nonce), secret);

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
            let remote_pubkey = secp256k1::PublicKey::parse_slice(ephem_pubkey, None)
                .map_err(|_| Discv5Error::InvalidRemotePublicKey)?;

            let sk = secp256k1::SecretKey::parse(&key.secret().to_bytes()).expect("valid key");

            let secret = secp256k1::SharedSecret::new(&remote_pubkey, &sk).map_err(|_| Discv5Error::KeyDerivationFailed)?;
            secret.as_ref().to_vec()
        }
    };

    derive_key(&secret, remote_id, local_id, id_nonce)
}

/* Nonce Signing */

/// Generates a signature of a nonce given a keypair. This prefixes 
pub fn sign_nonce(keypair: &Keypair, nonce: &Nonce) -> Result<Vec<u8>, Discv5Error> {
    let signing_nonce = generate_signing_nonce(nonce);

    match keypair {
        Keypair::Rsa(_) => unimplemented!("RSA keys are not supported"),
        Keypair::Ed25519(_) => unimplemented!("Ed25519 keys are not supported"),
        // builds a compact secp256k1 serialized compact signature
        Keypair::Secp256k1(key) => {
            let der_sig = key.secret().sign(&signing_nonce).map_err(|_| Discv5Error::Custom("Nonce signing failed"))?;
            Ok(Signature::parse_der(&der_sig).map_err(|_| Discv5Error::Custom("Invalid DER signature"))?.serialize().to_vec())
        }
    }
}

/// Verifies the authentication header nonce.
pub fn verify_authentication_nonce(
    remote_public_key: &PublicKey,
    nonce: &Nonce,
    sig: &[u8],
) -> bool {
    let signing_nonce = generate_signing_nonce(nonce);

    match remote_public_key {
        PublicKey::Rsa(_) => unimplemented!("RSA keys are not supported"),
        PublicKey::Ed25519(_) => unimplemented!("Ed25519 keys are not supported"),
        // verifies secp256k1 serialized compact signatures
        PublicKey::Secp256k1(pk) => {
            if let Ok(signature) = Signature::parse_slice(sig).map(|s| s.serialize_der()) {
                return pk.verify(&signing_nonce, signature.as_ref());
            }
            false
        }
    }
}

/// Builds the signature for a given nonce. This is the SHA256( 
fn generate_signing_nonce(id_nonce: &Nonce) -> Vec<u8> {
    let mut nonce = NONCE_PREFIX.as_bytes().to_vec();
    nonce.append(&mut id_nonce.to_vec());
    nonce
}

/* Decryption related functions */

/// Verifies the encoding and nonce signature given in the authentication header. If
/// the header contains an updated ENR, it is returned.
pub fn decrypt_authentication_header(
    auth_resp_key: &Key,
    header: &AuthHeader,
) -> Result<AuthResponse, Discv5Error> {
    if header.auth_scheme_name != KNOWN_SCHEME {
        return Err(Discv5Error::Custom("Invalid authentication scheme"));
    }

    // decrypt the auth-response
    let rlp_auth_response = decrypt_message(auth_resp_key, [0u8; 12], &header.auth_response, &[])?;
    let auth_response = rlp::decode::<AuthResponse>(&rlp_auth_response)
        .map_err(|e| Discv5Error::RLPError(e))?;
    Ok(auth_response)
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

/* Encryption related functions */

/// Encrypts a message with an authentication header.
pub fn encrypt_with_header(
    auth_resp_key: &Key,
    encryption_key: &Key,
    id_nonce: &Nonce,
    auth_pt: &[u8],
    message: &[u8],
    ephem_pubkey: &[u8],
    tag: &Tag,
) -> Result<(AuthHeader, Vec<u8>), Discv5Error> {
    let encrypted_auth_response  = encrypt_message(auth_resp_key, [0u8; 12], auth_pt, &[])?;

    // get the rlp_encoded auth_header
    let auth_tag: [u8; 12] = rand::random();
    let auth_header = AuthHeader::new(
        auth_tag,
        id_nonce.clone(),
        ephem_pubkey.to_vec(),
        encrypted_auth_response,
    );

    let mut auth_data = tag.to_vec();
    auth_data.append(&mut auth_header.encode());

    let message_ciphertext = encrypt_message(encryption_key, auth_tag, message, &auth_data)?;

    Ok((auth_header, message_ciphertext))
}

/// A wrapper around the underlying default AES_GCM implementation. This may be abstracted in the
/// future.
pub fn encrypt_message(
    key: &Key,
    nonce: AuthTag,
    message: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Discv5Error> {

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

        let node1_enr = EnrBuilder::new("v4").build(&node1_kp).unwrap();
        let node2_enr = EnrBuilder::new("v4").build(&node2_kp).unwrap();

        let nonce: Nonce = rand::random();

        let (key1, key2, key3, pk) =
            generate_session_keys(node1_enr.node_id(), &node2_enr, &nonce).unwrap();
        let (key4, key5, key6) = derive_keys_from_pubkey(
            &node2_kp,
            node2_enr.node_id(),
            node1_enr.node_id(),
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
