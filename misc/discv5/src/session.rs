use super::packet::{AuthHeader, AuthTag, NodeId, Nonce, Packet, Tag, MAGIC_LENGTH, TAG_LENGTH};
use super::service::Discv5Service;
use crate::handshake;
use enr::{Enr, EnrBuilder};
use futures::prelude::*;
use libp2p_core::identity::Keypair;
use log::{debug, error, warn};
use openssl::symm::{encrypt_aead, Cipher};
use rand;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::default::Default;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

pub struct SessionService {
    /// The local ENR.
    enr: Enr,
    /// The keypair to sign the ENR and set up encrypted communication with peers.
    keypair: Keypair,
    /// The node-id matching the ENR. (Stored prevent hashing on each request).
    node_id: NodeId,
    /// Pending raw requests. A list of raw messages we are awaiting a response from the remote
    /// for.
    pending_requests: HashMap<AuthTag, Request>,
    /// Pending messages. Messages awaiting to be sent, once a handshake has been established.
    pending_messages: HashMap<NodeId, Vec<Message>>,
    /// Session keys. Established sessions for each NodeId.
    session_keys: HashMap<NodeId, Session>,
    /// The discovery v5 service.
    service: Discv5Service,
}

impl SessionService {
    /// A new Session service which instantiates the UDP socket and builds a local ENR to send to
    /// other nodes. This requires a `Keypair` to sign the ENR and set up encrypted sessions
    /// with other peers. The `tcp` parameter can be optionally given to add to the ENR record to
    /// alert other peers of other listening ports.
    pub fn new(
        disc_socket_addr: SocketAddr,
        keypair: Keypair,
        tcp: Option<u16>,
    ) -> io::Result<Self> {
        // build the local ENR
        let enr = {
            let mut enr_builder = EnrBuilder::new();
            enr_builder
                .ip(disc_socket_addr.ip())
                .udp(disc_socket_addr.port());
            if let Some(tcp_port) = tcp {
                enr_builder.tcp(tcp_port);
            }
            enr_builder.build(&keypair).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Could not build the ENR record",
                )
            })
        }?;

        // generates the WHOAREYOU magic packet for the local node-id
        let node_id = enr.node_id();
        let magic = {
            let mut hasher = Sha256::new();
            hasher.input(node_id);
            hasher.input(b"WHOAREYOU");
            let mut magic: [u8; MAGIC_LENGTH] = [0; MAGIC_LENGTH];
            magic.copy_from_slice(&hasher.result());
            magic
        };

        Ok(SessionService {
            enr,
            keypair,
            node_id,
            pending_requests: HashMap::new(),
            pending_messages: HashMap::new(),
            session_keys: HashMap::new(),
            service: Discv5Service::new(disc_socket_addr, magic)?,
        })
    }

    /// Calculates the src `NodeId` given a tag.
    fn src_id(&self, tag: Tag) -> Tag {
        let hash = Sha256::digest(&self.node_id);
        let mut src_id: Tag = [0; TAG_LENGTH];
        for i in 0..TAG_LENGTH {
            src_id[i] = hash[i] ^ tag[i];
        }
        src_id
    }

    /// Calculates the tag given a `NodeId`.
    fn tag(&self, dst_id: NodeId) -> Tag {
        let hash = Sha256::digest(&dst_id);
        let mut tag: Tag = Default::default();
        for i in 0..TAG_LENGTH {
            tag[i] = hash[i] ^ self.node_id[i];
        }
        tag
    }

    /// Handles a WHOAREYOU packet that was received from the network.
    fn handle_whoareyou(
        &mut self,
        src: SocketAddr,
        src_id: NodeId,
        token: AuthTag,
        id_nonce: Nonce,
        enr_seq: u64,
    ) {
        // ignore, if the token doesn't match a pending request
        let req = match self.pending_requests.get(&token) {
            Some(r) => r,
            None => {
                debug!("WHOAREYOU packet received for an unknown request");
                return;
            }
        };

        // drop the packet if the request didn't come from the expected src or node-id
        if src != req.addr || src_id != req.enr.node_id() {
            warn!(
                "Invalid WHOAREYOU packet received from: {:?} ({:?})",
                src, src_id
            );
            return;
        }

        // get the messages that are waiting for an established session
        let mut messages = match self.pending_messages.get_mut(&src_id) {
            Some(v) => v,
            None => {
                // this should not happen
                error!("No pending messages found for WHOAREYOU request.");
                return;
            }
        };

        if messages.is_empty() {
            error!("No pending messages found for WHOAREYOU request.");
            return;
        }

        // generate the session key for the node
        let (encryption_key, decryption_key, auth_resp_key, ephem_pubkey) =
            match handshake::generate(&self.enr, &req.enr, &id_nonce) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Could not generate session key: {:?}", e);
                    return;
                }
            };

        // update the enr record if we need need to
        let mut updated_enr = None;
        if enr_seq < self.enr.seq {
            updated_enr = Some(&self.enr);
        }

        // encrypt the earliest message
        let earliest_message = messages.remove(0);

        // auth response header
        // sign the nonce (SHA256(nonce))
        let sig = match self.keypair.sign(&id_nonce) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Error signing WHOAREYOU Nonce. Ignoring  WHOAREYOU packet. Error: {:?}",
                    e
                );
                return;
            }
        };

        let auth_pt = AuthHeader::generate_response(&sig, updated_enr);
        let mut mac: [u8; 16] = Default::default();
        let mut ciphertext = match encrypt_aead(
            Cipher::aes_128_gcm(),
            &auth_resp_key,
            Some(&[0u8; 12]),
            &self.tag(src_id),
            &auth_pt,
            &mut mac,
        ) {
            Ok(v) => v,
            Err(e) => {
                error!("Could not encrypt authentication header. Ignoring WHOAREYOU packet. Error: {:?}", e);
                return;
            }
        };

        // concat the ciphertext with the MAC
        ciphertext.append(&mut mac.to_vec());

        // generate random auth-tag
        let auth_tag: [u8; 12] = rand::random();
        // get the rlp_encoded auth_header
        let auth_header = AuthHeader::new(auth_tag, ephem_pubkey, Box::new(ciphertext));

        // encrypt the original message
        let mut mac: [u8; 16] = Default::default();
        let mut auth_data = self.tag(src_id).to_vec();
        auth_data.append(&mut auth_header.encode());
        let mut msg_cipher = match encrypt_aead(
            Cipher::aes_128_gcm(),
            &encryption_key,
            Some(&auth_tag),
            &auth_data,
            &earliest_message.encode(),
            &mut mac,
        ) {
            Ok(v) => v,
            Err(e) => {
                error!("Could not encrypt authentication header message. Ignoring WHOAREYOUPacket. Error: {:?}", e);
                return;
            }
        };

        // concat the ciphertext with the MAC
        msg_cipher.append(&mut mac.to_vec());

        let response = Packet::AuthMessage {
            tag: self.tag(src_id),
            auth_header,
            message: Box::new(msg_cipher),
        };

        // send the response

        // add the keys to database with timeout

        // flush the message cache
    }

    pub fn poll(&mut self) -> Async<Discv5Message> {
        // poll the discv5 service
        loop {
            match self.service.poll() {
                Async::Ready((src, packet)) => {
                    match packet {
                        Packet::WhoAreYou {
                            tag,
                            token,
                            id_nonce,
                            enr_seq,
                            ..
                        } => {
                            let src_id = self.src_id(tag);
                            self.handle_whoareyou(src, src_id, token, id_nonce, enr_seq);
                        }
                        Packet::AuthMessage {
                            tag,
                            auth_header,
                            message,
                        } => {
                            let src_id = self.src_id(tag);
                            //    self.handle_auth_message(src, src_id, auth_header, message);
                        }
                        Packet::Message {
                            tag,
                            auth_tag,
                            message,
                        } => {
                            let src_id = self.src_id(tag);
                            //TODO: Send this upwards for higher-level logic
                            //self.handle_message(src, src_id, auth_tag, message);
                        }
                        Packet::RandomPacket { .. } => {} // this will not be decoded.
                    }
                }
                Async::NotReady => break,
            }
        }
        Async::NotReady
    }
}

pub struct Message {
    message_type: u8,
    message_data: Vec<u8>,
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut data = self.message_type.to_be_bytes().to_vec();
        let mut mut_data = self.message_data.clone();
        data.append(&mut mut_data);
        data
    }
}

pub struct Discv5Message;

pub struct Request {
    pub enr: Enr,
    pub packet: Packet,
    pub timeout: Instant,
    pub addr: SocketAddr,
}

impl Request {
    pub fn ip(&self) -> Option<IpAddr> {
        self.enr.ip()
    }
}

pub struct Session {
    key: AuthTag,
    expire: Instant,
}
