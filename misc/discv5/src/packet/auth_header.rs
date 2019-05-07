use super::AuthTag;
use libp2p_core::identity::PublicKey;
use log::debug;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

const AUTH_SCHEME_NAME: &str = "gsm";

/// The Authentication header.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthHeader {
    /// Authentication nonce.
    pub auth_tag: AuthTag,
    /// The authentication scheme.
    pub auth_scheme_name: &'static str,
    /// The public key as a generic.
    pub ephemeral_pubkey: PublicKey,
    /// Authentication response.
    pub auth_response: Box<Vec<u8>>,
}

impl AuthHeader {
    pub fn new(auth_tag: AuthTag, ephemeral_pubkey: PublicKey, resp: Box<Vec<u8>>) -> Self {
        AuthHeader {
            auth_tag,
            auth_scheme_name: AUTH_SCHEME_NAME,
            ephemeral_pubkey,
            auth_response: resp,
        }
    }
}

impl Encodable for AuthHeader {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.auth_tag.to_vec());
        s.append(&self.auth_scheme_name);
        s.append(&self.ephemeral_pubkey.clone().into_protobuf_encoding());
        s.append(&self.auth_response.to_vec());
    }
}

impl Decodable for AuthHeader {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !rlp.is_list() {
            debug!(
                "Failed to decode Authentication header. Not an RLP list: {}",
                rlp
            );
            return Err(DecoderError::RlpExpectedToBeList);
        }

        let mut decoded_list = match rlp.as_list::<Vec<u8>>() {
            Ok(v) => v,
            Err(_) => {
                debug!("Could not decode Authentication header: {}", rlp);
                return Err(DecoderError::Custom("List decode fail"));
            }
        };

        if decoded_list.len() != 4 {
            debug!("Failed to decode Authentication header. Incorrect list size. Length: {}, expected 4", decoded_list.len());
            return Err(DecoderError::RlpExpectedToBeList);
        }

        let auth_response = decoded_list.pop().expect("List is long enough");
        let pubkey_bytes = decoded_list.pop().expect("List is long enough");
        let auth_scheme_bytes = decoded_list.pop().expect("List is long enough");
        let auth_tag_bytes = decoded_list.pop().expect("List is long enough");

        let mut auth_tag: AuthTag = Default::default();
        auth_tag.clone_from_slice(&auth_tag_bytes);

        // currently only support gsm scheme
        if String::from_utf8_lossy(&auth_scheme_bytes) != "gsm" {
            debug!(
                "Failed to decode Authentication header. Unknown auth scheme: {}",
                String::from_utf8_lossy(&auth_scheme_bytes)
            );
            return Err(DecoderError::Custom("Invalid Authentication Scheme"));
        }

        let ephemeral_pubkey = PublicKey::from_protobuf_encoding(&pubkey_bytes).map_err(|_| {
            debug!(
                "Failed to decode Authentication header. Unknown publickey encoding: {:?}",
                pubkey_bytes
            );
            DecoderError::Custom("Unknown public key encoding")
        })?;

        Ok(AuthHeader {
            auth_tag,
            auth_scheme_name: "gsm",
            ephemeral_pubkey,
            auth_response: Box::new(auth_response),
        })
    }
}
