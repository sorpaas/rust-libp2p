use super::packet::{
    AuthHeader, AuthResponse, AuthTag, NodeId, Nonce, Packet, Tag, MAGIC_LENGTH, TAG_LENGTH,
};
use super::service::Discv5Service;
use crate::crypto;
use enr::{Enr, EnrBuilder};
use futures::prelude::*;
use libp2p_core::identity::Keypair;
use log::{debug, error, warn};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::default::Default;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Minutes before the keys of an established connection timeout.
//TODO: This is short for testing.
const SESSION_TIMEOUT: u64 = 30;

const REQUEST_TIMEOUT: u64 = 10;

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
    /// Keep track of sent WHOAREYOU packets separately for quick searching.
    whoareyou_requests: HashMap<NodeId, Request>,
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
            whoareyou_requests: HashMap::new(),
            pending_messages: HashMap::new(),
            session_keys: HashMap::new(),
            service: Discv5Service::new(disc_socket_addr, magic)?,
        })
    }

    /// Calculates the src `NodeId` given a tag.
    fn src_id(&self, tag: &Tag) -> Tag {
        let hash = Sha256::digest(&self.node_id);
        let mut src_id: Tag = [0; TAG_LENGTH];
        for i in 0..TAG_LENGTH {
            src_id[i] = hash[i] ^ tag[i];
        }
        src_id
    }

    /// Calculates the tag given a `NodeId`.
    fn tag(&self, dst_id: &NodeId) -> Tag {
        let hash = Sha256::digest(dst_id);
        let mut tag: Tag = Default::default();
        for i in 0..TAG_LENGTH {
            tag[i] = hash[i] ^ self.node_id[i];
        }
        tag
    }

    // verify that a received packet came from a pending request with the correct source
    #[inline]
    fn verify_packet(
        &mut self,
        src: SocketAddr,
        src_id: &NodeId,
        auth_tag: &AuthTag,
    ) -> Result<Request, String> {
        // the auth-tag must match a pending request
        let req = self
            .pending_requests
            .remove(auth_tag)
            .ok_or_else(|| String::from("Packet references an unknown or expired request"))?;

        // the referenced request must come from the expected src or node-id
        if src != req.dst || src_id != &req.node_id {
            // add the request back
            self.pending_requests.insert(auth_tag.clone(), req);
            return Err(String::from("Incorrect source"));
        }
        Ok(req)
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
        let req = match self.verify_packet(src, &src_id, &token) {
            Ok(v) => v,
            Err(e) => {
                debug!(
                    "WHOAREYOU packet verification failed: src: {:?}, error: {}",
                    src_id, e
                );
                return;
            }
        };

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
            match crypto::generate_session_keys(&self.node_id, &req.enr, &id_nonce) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Could not generate session key: {:?}", e);
                    return;
                }
            };

        // update the enr record if we need need to
        let mut updated_enr = None;
        if enr_seq < self.enr.seq {
            updated_enr = Some(self.enr.clone());
        }

        // encrypt the earliest message
        let earliest_message = messages.remove(0);

        // sign the nonce
        let mut nonce = b"discovery-id-nonce".to_vec();
        nonce.append(&mut id_nonce.to_vec());
        let sig = match self.keypair.sign(&nonce) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Error signing WHOAREYOU Nonce. Ignoring  WHOAREYOU packet. Error: {:?}",
                    e
                );
                return;
            }
        };

        // generate the auth response to be encrypted
        let auth_pt = AuthResponse::new(&sig, updated_enr).encode();

        // encrypt the earliest packet with the authentication header
        let packet = match crypto::encrypt_with_header(
            &auth_resp_key,
            &encryption_key,
            &auth_pt,
            &earliest_message.encode(),
            &ephem_pubkey,
            &self.tag(&src_id),
        ) {
            Ok(v) => v,
            Err(e) => {
                error!("Could not encrypt message: {:?}", e);
                return;
            }
        };

        // send the response
        self.service.send(src, packet);

        // add the keys to memory with a timeout
        let session = Session {
            encryption_key,
            decryption_key: decryption_key.clone(),
            timeout: Instant::now() + Duration::from_secs(SESSION_TIMEOUT),
        };
        self.session_keys.insert(src_id.clone(), session);

        // flush the message cache
        self.flush_messages(src, &src_id, &req.enr, &decryption_key);
    }

    // Processing logic for receiving a message containing an Authentication header
    fn handle_auth_message(
        &mut self,
        src: SocketAddr,
        src_id: &NodeId,
        auth_header: AuthHeader,
        message: &[u8],
    ) {
        // Needs to match an outgoing WHOAREYOU packet (so we have the required nonce to be signed). If it doesn't we drop the packet. This will
        // lead to future outgoing WHOAREYOU packets if they proceed to send further encrypted
        // packets.
        let req = self.whoareyou_requests.remove(src_id);

        if req.is_none() {
            warn!("Received an authenticated header without a known WHOAREYOU packet. Dropping");
            return;
        }
        let req = req.expect("not empty");

        // verify the source ip, avoid spam and signature verification calculations from malicious packets.
        // the referenced request must come from the expected src or node-id
        if src != req.dst || src_id != &req.node_id {
            warn!("Received an authenticated header from incorrect source. Expected id: {:?}, actual id: {:?}, expected source: {:?} actual source: {:?}", req.node_id, src_id, req.dst, src);
            // add the request back
            self.whoareyou_requests.insert(src_id.clone(), req);
            return;
        }

        // get the nonce
        let id_nonce = match req.packet {
            _ => unreachable!("Coding error if there is not a WHOAREYOU packet in this request"),
            Packet::WhoAreYou { id_nonce, .. } => id_nonce,
        };

        // obtain the session keys
        let (decryption_key, encryption_key, auth_resp_key) = match crypto::derive_keys_from_header(
            &self.keypair,
            &self.node_id,
            &req.node_id,
            &id_nonce,
            auth_header,
        ) {
            Ok(v) => v,
            Err(e) => {
                warn!("Invalid Authentication header: {:?}", e);
                return;
            }
        };

        // verify the authentication header
    }

    // encrypts and sends any messages that were waiting for a session to be established
    #[inline]
    fn flush_messages(&mut self, src: SocketAddr, src_id: &NodeId, enr: &Enr, key: &[u8; 16]) {
        let mut messages = match self.pending_messages.remove(src_id) {
            Some(v) => v,
            None => {
                return;
            }
        };

        let tag = self.tag(&src_id);
        for _ in 0..messages.len() {
            let msg = messages.pop().expect("item must exist");
            let (msg_cipher, auth_tag) =
                match crypto::encrypt_message(key, &msg.encode(), &tag, None) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Failed to encrypt message: {:?}, error: {:?}", msg, e);
                        return;
                    }
                };
            let packet = Packet::Message {
                tag,
                auth_tag,
                message: Box::new(msg_cipher),
            };
            self.send_packet(src, enr, packet, &auth_tag);
        }

        debug_assert!(messages.is_empty());
    }

    // wrapper around service.send() that adds all sent messages to the pending_requests hashmap
    #[inline]
    fn send_packet(&mut self, dst: SocketAddr, dst_enr: &Enr, packet: Packet, auth_tag: &AuthTag) {
        self.service.send(dst, packet.clone());
        let dst_id = dst_enr.node_id();
        let request = Request {
            dst,
            enr: dst_enr.clone(),
            node_id: dst_id.clone(),
            packet,
            timeout: Instant::now() + Duration::from_secs(REQUEST_TIMEOUT),
        };

        match &request.packet {
            Packet::WhoAreYou { .. } => self.whoareyou_requests.insert(dst_id, request),
            _ => self.pending_requests.insert(auth_tag.clone(), request),
        };
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
                            let src_id = self.src_id(&tag);
                            self.handle_whoareyou(src, src_id, token, id_nonce, enr_seq);
                        }
                        Packet::AuthMessage {
                            tag,
                            auth_header,
                            message,
                        } => {
                            let src_id = self.src_id(&tag);
                            self.handle_auth_message(src, &src_id, auth_header, &message);
                        }
                        Packet::Message {
                            tag,
                            auth_tag,
                            message,
                        } => {
                            let src_id = self.src_id(&tag);
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

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Request {
    pub dst: SocketAddr,
    pub enr: Enr,
    // This is stored separately to prevent rehashing the ENR.
    pub node_id: NodeId,
    pub packet: Packet,
    pub timeout: Instant,
}

impl Request {
    pub fn ip(&self) -> Option<IpAddr> {
        self.enr.ip()
    }
}

pub struct Session {
    encryption_key: [u8; 16],
    decryption_key: [u8; 16],
    timeout: Instant,
}
