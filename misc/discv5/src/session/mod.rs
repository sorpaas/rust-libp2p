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
use crate::session_service::SESSION_TIMEOUT;
use crate::Discv5Error;
use enr::{Enr, NodeId};
use libp2p_core::identity::Keypair;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::timer::Delay;
use zeroize::Zeroize;

mod crypto;

const WHOAREYOU_STRING: &str = "WHOAREYOU";
const NONCE_STRING: &str = "discovery-id-nonce";

/// Manages active handshakes and connections between nodes in discv5. There are three main states
/// a session can be in, intializing (`WhoAreYouSent` or `RandomSent`), `Untrusted` (when the
/// socket address of the ENR doesn't match the `last_seen_socket`) and `Established` (the session
/// has been successfully established).
pub struct Session {
    /// The current state of the Session
    status: SessionStatus,

    /// The ENR of the remote node. This may be unknown during `WhoAreYouSent` states.
    remote_enr: Option<Enr>,

    /// The ephemeral public key of the session.
    ephem_pubkey: Option<Vec<u8>>,

    /// The established session keys.
    keys: Keys,

    /// Last seen IP address and port. This is used to determine if the session is trusted or not.
    last_seen_socket: SocketAddr,

    /// The Delay when this session expires.
    timeout: Option<Delay>,
}

#[derive(Zeroize)]
pub struct Keys {
    /// The Authentication response key.
    pub auth_resp_key: [u8; 16],

    /// The encryption key.
    pub encryption_key: [u8; 16],

    /// The decryption key.
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
    /// A WHOAREYOU packet has been sent, and the Session is awaiting an Authentication response.
    WhoAreYouSent,

    /// A RANDOM packet has been sent and the Session is awaiting a WHOAREYOU response.
    RandomSent,

    /// A Session has been established, but the IP address of the remote ENR does not match the IP
    /// of the source. In this state, the service will respond to requests, but does not treat the node as
    /// connected until the IP is updated to match the source IP.
    Untrusted,

    /// A Session has been established and the ENR IP matches the source IP.
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
            timeout: None, // don't timeout until the session is established
            last_seen_socket: "0.0.0.0:0".parse::<SocketAddr>().expect("Valid Socket"),
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
                token: auth_tag,
                id_nonce,
                enr_seq,
            }
        };

        let session = Session {
            status: SessionStatus::WhoAreYouSent,
            remote_enr,
            ephem_pubkey: None,
            keys: Keys::new(),
            timeout: None, // don't timeout until the session is established
            last_seen_socket: "0.0.0.0:0".parse::<SocketAddr>().expect("Valid Socket"),
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
            message: cipher,
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
            tag,
            auth_header,
            message: ciphertext,
        })
    }

    pub fn generate_nonce(id_nonce: Nonce) -> Vec<u8> {
        let mut nonce = NONCE_STRING.as_bytes().to_vec();
        nonce.append(&mut id_nonce.to_vec());
        nonce
    }

    /// Generates a session from an authentication header. If the IP of the ENR does not match the
    /// source IP address, we consider this session untrusted. The output returns a boolean which
    /// specifies if the Session is trusted or not.
    pub fn establish_from_header(
        &mut self,
        tag: Tag,
        local_keypair: &Keypair,
        local_id: &NodeId,
        remote_id: &NodeId,
        id_nonce: Nonce,
        auth_header: &AuthHeader,
    ) -> Result<bool, Discv5Error> {
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

        // check and verify a potential ENR update
        if let Some(enr) = auth_response.updated_enr {
            if let Some(remote_enr) = &self.remote_enr {
                // verify the enr-seq number
                if remote_enr.seq() < enr.seq() {
                    self.remote_enr = Some(enr.clone());
                } // ignore ENR's that have a lower seq number
            } else {
                // update the ENR
                self.remote_enr = Some(enr.clone());
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

        self.status = SessionStatus::Untrusted;
        // output if the session is trusted or untrusted
        Ok(self.update_trusted())
    }

    pub fn decrypt_message(
        &self,
        nonce: AuthTag,
        message: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Discv5Error> {
        crypto::decrypt_message(&self.keys.decryption_key, nonce, message, aad)
    }

    pub fn update_enr(&mut self, enr: Enr) -> bool {
        if let Some(remote_enr) = &self.remote_enr {
            if remote_enr.seq() < enr.seq() {
                self.remote_enr = Some(enr);
                // ENR has been updated. Check if the state can be promoted to trusted
                return self.update_trusted();
            }
        }
        false
    }

    /// Updates the trusted status of a Session. It can be promoted to an `established` state, or
    /// demoted to an `untrusted` state. This value returns true if the Session has been
    /// promoted.
    pub fn update_trusted(&mut self) -> bool {
        if let SessionStatus::Untrusted = self.status {
            if let Some(remote_enr) = &self.remote_enr {
                if Some(self.last_seen_socket) == remote_enr.udp_socket() {
                    self.status = SessionStatus::Established;
                    return true;
                }
            }
        } else if let SessionStatus::Established = self.status {
            if let Some(remote_enr) = &self.remote_enr {
                if Some(self.last_seen_socket) != remote_enr.udp_socket() {
                    self.status = SessionStatus::Untrusted;
                }
            }
        }
        false
    }

    pub fn set_last_seen_socket(&mut self, socket: SocketAddr) {
        self.last_seen_socket = socket;
    }

    pub fn increment_timeout(&mut self, secs: u64) {
        self.timeout = Some(Delay::new(Instant::now() + Duration::from_secs(secs)));
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

    pub fn is_trusted(&self) -> bool {
        if let SessionStatus::Established = self.status {
            true
        } else {
            false
        }
    }

    pub fn established(&self) -> bool {
        match self.status {
            SessionStatus::WhoAreYouSent => false,
            SessionStatus::RandomSent => false,
            SessionStatus::Established => true,
            SessionStatus::Untrusted => true,
        }
    }
}
