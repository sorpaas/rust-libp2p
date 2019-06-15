//! The `Session` struct handles the stages of creating and establishing a handshake with a
//! peer.
//!
//! There are ways a Session gets initialised.
//!
//! - An message to an unknown peer is requested. In this case a RANDOM packet is sent to the peer.
//! This session is created using the `new_random()` function.
//! - A message was received from an unknown peer and we start the `Session` by sending a
//! WHOAREYOU message.
//!
//! A `Session` is responsible for generating,deriving and holding keys for sessions between
//! peers.

use super::packet::{AuthHeader, AuthTag, Nonce, Packet, Tag, MAGIC_LENGTH};
use crate::crypto;
use crate::Discv5Error;
use enr::{Enr, NodeId};
use libp2p_core::identity::Keypair;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio::timer::Delay;
use zeroize::Zeroize;

const WHOAREYOU_STRING: &'static str = "WHOAREYOU";
const NONCE_STRING: &'static str = "discovery-id-nonce";

//TODO: This is short for testing.
const SESSION_TIMEOUT: u64 = 30;

pub struct Session {
    status: SessionStatus,
    remote_enr: Option<Enr>,       // can be None for WHOAREYOU sessions.
    ephem_pubkey: Option<Vec<u8>>, // ephemeral key is stored as encoded bytes
    keys: Keys,
    timeout: Option<Delay>,
}

#[derive(Zeroize)]
pub struct Keys {
    pub auth_resp_key: [u8; 16],
    pub encryption_key: [u8; 16],
    pub decryption_key: [u8; 16],
}

impl Keys {
    pub fn new() -> Self {
        Keys {
            auth_resp_key: [0u8; 16],
            encryption_key: [0u8; 16],
            decryption_key: [0u8; 16],
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum SessionStatus {
    WhoAreYouSent, // WHOAREYOU packet has been sent, awaiting an auth response
    RandomSent,    // Sent a random packet, awaiting a WHOAREYOU response
    Established,
}

impl Session {
    pub fn new_random(tag: Tag, remote_enr: Enr) -> (Self, Packet) {
        let random_packet = Packet::random(tag);

        let session = Session {
            status: SessionStatus::RandomSent,
            remote_enr: Some(remote_enr),
            ephem_pubkey: None,
            keys: Keys::new(),
            timeout: None, // we don't timeout until the session is established
        };

        (session, random_packet)
    }

    pub fn new_whoareyou(
        tag: Tag,
        node_id: &NodeId,
        enr_seq: u64,
        remote_enr: Option<Enr>,
        auth_tag: AuthTag,
    ) -> (Self, Packet) {
        // build the WHOAREYOU packet
        let whoareyou_packet = {
            let magic = {
                let mut hasher = Sha256::new();
                hasher.input(node_id.raw());
                hasher.input(WHOAREYOU_STRING.as_bytes());
                let mut magic = [0u8; MAGIC_LENGTH];
                magic.copy_from_slice(&hasher.result());
                magic
            };

            let id_nonce: Nonce = rand::random();

            Packet::WhoAreYou {
                tag,
                magic,
                token: auth_tag.clone(),
                id_nonce,
                enr_seq,
            }
        };

        let session = Session {
            status: SessionStatus::WhoAreYouSent,
            remote_enr,
            ephem_pubkey: None,
            keys: Keys::new(),
            timeout: None, // we don't timeout until the session is established
        };

        (session, whoareyou_packet)
    }

    fn generate_keys(
        &mut self,
        local_node_id: &NodeId,
        id_nonce: &Nonce,
    ) -> Result<(), Discv5Error> {
        let (encryption_key, decryption_key, auth_resp_key, ephem_pubkey) =
            crypto::generate_session_keys(
                local_node_id,
                self.remote_enr
                    .as_ref()
                    .expect("Should never be None at this point"),
                id_nonce,
            )?;

        self.ephem_pubkey = Some(ephem_pubkey);

        self.keys = Keys {
            encryption_key,
            auth_resp_key,
            decryption_key,
        };

        self.timeout = Some(Delay::new(
            Instant::now() + Duration::from_secs(SESSION_TIMEOUT),
        ));

        self.status = SessionStatus::Established;
        Ok(())
    }

    pub fn encrypt_message(&self, tag: Tag, message: &[u8]) -> Result<Packet, Discv5Error> {
        //TODO: Establish a counter to prevent repeats of nonce
        let auth_tag: AuthTag = rand::random();

        let cipher = crypto::encrypt_message(&self.keys.encryption_key, auth_tag, message, &tag)?;

        Ok(Packet::Message {
            tag,
            auth_tag,
            message: Box::new(cipher),
        })
    }

    pub fn encrypt_with_header(
        &mut self,
        tag: Tag,
        local_node_id: &NodeId,
        id_nonce: &Nonce,
        auth_pt: &[u8],
        message: &[u8],
    ) -> Result<Packet, Discv5Error> {
        // generate the session keys
        self.generate_keys(local_node_id, id_nonce)?;

        // encrypt the message with the newly generated session keys
        let (auth_header, ciphertext) = crypto::encrypt_with_header(
            &self.keys.auth_resp_key,
            &self.keys.encryption_key,
            auth_pt,
            message,
            &(self.ephem_pubkey.clone().expect("Keys have been generated")),
            &tag,
        )?;

        Ok(Packet::AuthMessage {
            tag: tag,
            auth_header,
            message: Box::new(ciphertext),
        })
    }

    pub fn generate_nonce(id_nonce: Nonce) -> Vec<u8> {
        let mut nonce = NONCE_STRING.as_bytes().to_vec();
        nonce.append(&mut id_nonce.to_vec());
        nonce
    }

    pub fn generate_keys_from_header(
        &mut self,
        tag: Tag,
        local_keypair: &Keypair,
        local_id: &NodeId,
        remote_id: &NodeId,
        id_nonce: Nonce,
        auth_header: &AuthHeader,
    ) -> Result<Option<Enr>, Discv5Error> {
        // generate session keys

        let (decryption_key, encryption_key, auth_resp_key) = crypto::derive_keys_from_pubkey(
            local_keypair,
            local_id,
            remote_id,
            &id_nonce,
            &auth_header.ephemeral_pubkey,
        )?;

        // decrypt the authentication header
        let auth_response =
            crypto::decrypt_authentication_header(&auth_resp_key, auth_header, &tag)?;

        // to inform if we have updated the ENR record of the session.
        let mut updated_enr = None;

        // check and verify a potential ENR update
        if let Some(enr) = auth_response.updated_enr {
            if let Some(remote_enr) = &self.remote_enr {
                // verify the enr-seq number
                if remote_enr.seq < enr.seq {
                    self.remote_enr = Some(enr.clone());
                    updated_enr = self.remote_enr.clone();
                } // ignore ENR's that have a lower seq number
            } else {
                // update the ENR
                self.remote_enr = Some(enr.clone());
                updated_enr = self.remote_enr.clone();
            }
        } else if self.remote_enr.is_none() {
            // didn't receive the remote's ENR
            return Err(Discv5Error::InvalidEnr);
        }

        // enr must exist here
        let remote_public_key = self
            .remote_enr
            .as_ref()
            .expect("ENR Must exist")
            .public_key();
        // verify the auth header nonce
        if !crypto::verify_authentication_nonce(
            &remote_public_key,
            &Session::generate_nonce(id_nonce),
            &auth_response.signature,
        ) {
            return Err(Discv5Error::InvalidSignature);
        }

        // session has been established
        self.ephem_pubkey = Some(auth_header.ephemeral_pubkey.clone());
        self.keys = Keys {
            encryption_key,
            auth_resp_key,
            decryption_key,
        };
        self.timeout = Some(Delay::new(
            Instant::now() + Duration::from_secs(SESSION_TIMEOUT),
        ));

        self.status = SessionStatus::Established;

        Ok(updated_enr)
    }

    pub fn decrypt_message(
        &self,
        nonce: AuthTag,
        message: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Discv5Error> {
        crypto::decrypt_message(&self.keys.decryption_key, nonce, message, aad)
    }

    pub fn timeout(&mut self) -> &mut Option<Delay> {
        &mut self.timeout
    }

    pub fn status(&self) -> SessionStatus {
        self.status
    }

    pub fn remote_enr(&self) -> &Option<Enr> {
        &self.remote_enr
    }

    pub fn established(&self) -> bool {
        match self.status {
            SessionStatus::WhoAreYouSent => false,
            SessionStatus::RandomSent => false,
            SessionStatus::Established => true,
        }
    }
}
