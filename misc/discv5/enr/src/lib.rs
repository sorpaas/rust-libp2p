//! Ethereum Node Record (ENR)
//!
//! This crate contains an Ethereum Node Record as specified by [EIP-778](https://eips.ethereum.org/EIPS/eip-778) extended to allow for the use of a range of public key types.

use libp2p_core::identity::{ed25519, Keypair, PublicKey};
use log::debug;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use secp256k1::{Message, Signature};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;
use std::net::IpAddr;

use libp2p_core::identity::rsa;
use libp2p_core::identity::secp256k1 as libp2p_secp256k1;

const MAX_ENR_SIZE: usize = 300;

/// ENR Record
#[derive(Clone, Debug)]
pub struct Enr {
    /// ENR sequence number.
    seq: u64,
    /// Key-value contents of the ENR.
    content: HashMap<String, Vec<u8>>,
    /// RLP-encoded content. This exists because Hashmaps do not preserve ordering and the signature
    /// is order-dependant. This is updated every time the ENR is updated.
    rlp_content: Vec<u8>,
    /// The signature of the ENR record.
    signature: Vec<u8>,
}

impl Enr {
    /// Evaluates the RLP content of the ENR record.
    pub fn rlp_content(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.begin_list(self.content.len() * 2 + 1);
        stream.append(&self.seq);
        for (k, v) in self.content.iter() {
            stream.append(k);
            stream.append(v);
        }
        stream.drain()
    }

    /// Returns the IP address of the ENR record if it is defined.
    pub fn ip(&self) -> Option<IpAddr> {
        if let Some(ip_bytes) = self.content.get("ip") {
            return match ip_bytes.len() {
                4 => {
                    let mut ip: [u8; 4] = [0; 4];
                    ip.copy_from_slice(ip_bytes);
                    Some(IpAddr::from(ip))
                }
                16 => {
                    let mut ip: [u8; 16] = [0; 16];
                    ip.copy_from_slice(ip_bytes);
                    Some(IpAddr::from(ip))
                }
                _ => None,
            };
        }
        None
    }

    /// Returns the Id of ENR record if it is defined.
    pub fn id(&self) -> Option<String> {
        if let Some(id_bytes) = self.content.get("id") {
            return Some(String::from_utf8_lossy(id_bytes).to_string());
        }
        None
    }

    /// Returns the tcp port of ENR record if it is defined.
    pub fn tcp(&self) -> Option<u16> {
        if let Some(tcp_bytes) = self.content.get("tcp") {
            if tcp_bytes.len() <= 2 {
                let mut tcp: [u8; 2] = [0; 2];
                tcp[2 - tcp_bytes.len()..].copy_from_slice(tcp_bytes);
                return Some(u16::from_be_bytes(tcp));
            }
        }
        None
    }

    /// Returns the udp port of ENR record if it is defined.
    pub fn udp(&self) -> Option<u16> {
        if let Some(udp_bytes) = self.content.get("udp") {
            if udp_bytes.len() <= 2 {
                let mut udp: [u8; 2] = [0; 2];
                udp[2 - udp_bytes.len()..].copy_from_slice(udp_bytes);
                return Some(u16::from_be_bytes(udp));
            }
        }
        None
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the public key of the ENR record if it is defined and it's type is known.
    pub fn pubkey(&self) -> Option<PublicKey> {
        // try known pubkeys.
        // TODO: Build a mapping of known pubkeys
        // secp256k1

        if let Some(pubkey_bytes) = self.content.get("secp256k1") {
            return libp2p_secp256k1::PublicKey::decode(pubkey_bytes)
                .map(PublicKey::Secp256k1)
                .ok();
        } else if let Some(pubkey_bytes) = self.content.get("ed25519") {
            return ed25519::PublicKey::decode(pubkey_bytes)
                .map(PublicKey::Ed25519)
                .ok();
        } else if let Some(pubkey_bytes) = self.content.get("rsa") {
            return rsa::PublicKey::decode_x509(pubkey_bytes)
                .map(PublicKey::Rsa)
                .ok();
        }
        None
    }

    /// Verify the signature of the ENR record.
    // Libp2p uses Sha256 hashes - Some inefficiencies here using keccak (for compatibility).
    // TODO: Add keccak support for libp2p signing.
    pub fn verify(&self) -> bool {
        let keccak_hash = Keccak256::digest(&self.rlp_content);

        if let Some(pubkey) = self.pubkey() {
            if let Ok(sig) =
                Signature::from_compact(&self.signature).and_then(|s| Ok(s.serialize_der()))
            {
                return pubkey.verify_raw(&keccak_hash, &sig);
            }
        }
        false
    }
}

pub struct EnrBuilder {
    seq: u64,
    content: HashMap<String, Vec<u8>>,
}

impl EnrBuilder {
    pub fn new() -> Self {
        EnrBuilder {
            seq: 0,
            content: HashMap::new(),
        }
    }

    pub fn seq(&mut self, seq: u64) -> &mut Self {
        self.seq = seq;
        self
    }
    pub fn add_value(&mut self, key: String, value: Vec<u8>) -> &mut Self {
        self.content.insert(key, value);
        self
    }

    pub fn rlp_content(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.begin_list(self.content.len() * 2 + 1);
        stream.append(&self.seq);
        for (k, v) in self.content.iter() {
            stream.append(k);
            stream.append(v);
        }
        stream.drain()
    }

    pub fn build(&mut self, key: Keypair) -> Result<Enr, EnrError> {
        // add the public key to the content
        let (pubkey_string, pubkey_bytes) = match key.public() {
            PublicKey::Ed25519(key) => (String::from("ed25519"), key.encode().to_vec()),
            PublicKey::Rsa(key) => (String::from("rsa"), key.encode_x509().to_vec()),
            PublicKey::Secp256k1(key) => {
                // uses compressed form, single point, 33 bytes
                (String::from("secp256k1"), key.encode().to_vec())
            }
        };

        self.add_value(pubkey_string, pubkey_bytes);

        let rlp_content = self.rlp_content();

        let hash = Keccak256::digest(&rlp_content);

        // construct compact signature
        let signature = {
            let der_signature = key.sign_raw(&hash).map_err(|_| EnrError::SigningError)?;
            Signature::from_der(&der_signature)
                .map_err(|_| EnrError::SigningError)?
                .serialize_compact()
                .to_vec()
        };

        // check the size of the record
        if rlp_content.len() + signature.len() + 8 > MAX_ENR_SIZE {
            return Err(EnrError::ExceedsMaxSize);
        }

        Ok(Enr {
            seq: self.seq,
            content: self.content.clone(),
            rlp_content,
            signature,
        })
    }
}

impl Encodable for Enr {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(self.content.len() * 2 + 2);
        s.append(&self.signature);
        s.append(&self.seq);
        for (k, v) in self.content.iter() {
            s.append(k);
            s.append(v);
        }
    }
}

impl Decodable for Enr {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !rlp.is_list() {
            debug!("Failed to decode ENR. Not an RLP list: {}", rlp);
            return Err(DecoderError::RlpExpectedToBeList);
        }

        let mut decoded_list = rlp.as_list::<Vec<u8>>().map_err(|_| {
            debug!("Could not decode content: {}", rlp);
            DecoderError::Custom("List decode fail")
        })?;

        if decoded_list.len() % 2 != 0 {
            debug!("Failed to decode ENR. List size is not a multiple of 2.");
            return Err(DecoderError::Custom("List not a multiple of two"));
        }

        let signature = decoded_list.remove(0);
        let seq_bytes = decoded_list.remove(0);

        if seq_bytes.len() > 8 {
            debug!("Failed to decode ENR. Sequence number is not a u64.");
            return Err(DecoderError::Custom("Invalid Sequence number"));
        }

        // build u64 from big endian vec<u8>
        let mut seq: [u8; 8] = [0; 8];
        seq[8 - seq_bytes.len()..].copy_from_slice(&seq_bytes);
        let seq = u64::from_be_bytes(seq);

        // keep track of the current rlp ordering
        let mut rlp_encodings: Vec<Vec<u8>> = Vec::new();

        let mut content = HashMap::new();
        for _ in 0..decoded_list.len() / 2 {
            let value = decoded_list.pop().expect("Large enough");
            let key = decoded_list.pop().expect("Large enough");

            // keep current ordering in reverse
            rlp_encodings.push(value.clone());
            rlp_encodings.push(key.clone());

            let key = String::from_utf8_lossy(&key);
            content.insert(key.to_string(), value);
        }

        rlp_encodings.push(seq_bytes);
        let rev_rlp_encodings: Vec<Vec<u8>> = rlp_encodings.iter().cloned().rev().collect();

        let rlp_content = rlp::encode_list::<Vec<u8>, Vec<u8>>(&rev_rlp_encodings);

        let enr = Enr {
            seq,
            signature,
            content,
            rlp_content,
        };

        // verify the signature before returning
        if !enr.verify() {
            return Err(DecoderError::Custom("Invalid Signature"));
        }
        Ok(enr)
    }
}

#[derive(Clone, Debug)]
pub enum EnrError {
    ExceedsMaxSize,
    SigningError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn check_test_vector() {
        let valid_record = hex::decode("f884b8407098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c01826964827634826970847f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31388375647082765f").unwrap();
        let signature = hex::decode("7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c").unwrap();
        let expected_pubkey =
            hex::decode("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138")
                .unwrap();

        let enr = rlp::decode::<Enr>(&valid_record).unwrap();

        let pubkey = match enr.pubkey().unwrap() {
            PublicKey::Secp256k1(key) => Some(key.encode()),
            _ => None,
        };

        assert_eq!(enr.ip(), Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(enr.id(), Some(String::from("v4")));
        assert_eq!(enr.udp(), Some(30303));
        assert_eq!(enr.tcp(), None);
        assert_eq!(enr.signature(), &signature[..]);
        assert_eq!(pubkey.unwrap().to_vec(), expected_pubkey);
    }

    #[test]
    fn test_encode_decode() {
        let key = Keypair::generate_secp256k1();
        let enr = {
            let mut builder = EnrBuilder::new();
            builder.add_value(String::from("id"), b"v4".to_vec());
            builder.add_value(
                String::from("ip"),
                Ipv4Addr::new(127, 0, 0, 1).octets().to_vec(),
            );
            builder.add_value(
                String::from("tcp"),
                u16::from(3000u16).to_be_bytes().to_vec(),
            );
            builder.build(key).unwrap()
        };

        dbg!(enr.verify());
    }

}
