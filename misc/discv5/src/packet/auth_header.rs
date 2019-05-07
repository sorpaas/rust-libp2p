use super::AuthTag;
use libp2p_core::identity::PublicKey;
use rlp::{Decodable, Encodable, RlpStream};

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

/*
impl Decodable for AuthHeader {

}
*/
