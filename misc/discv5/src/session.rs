use super::packet::{
    AuthHeader, AuthResponse, AuthTag, NodeId, Nonce, Packet, Tag, MAGIC_LENGTH, TAG_LENGTH,
};
use super::service::Discv5Service;
use crate::crypto;
use crate::message::ProtocolMessage;
use enr::{Enr, EnrBuilder};
use fnv::FnvHashMap;
use futures::prelude::*;
use hex;
use libp2p_core::identity::Keypair;
use log::{debug, error, warn};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::default::Default;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::timer::Interval;

mod tests;

/// Seconds before the keys of an established connection timeout.
//TODO: This is short for testing.
const SESSION_TIMEOUT: u64 = 30;
const REQUEST_TIMEOUT: u64 = 10;
const REQUEST_RETRIES: u8 = 2;
const HEARTBEAT_INTERVAL: u64 = 5;

pub struct SessionService {
    /// Queue of events produced by the session service.
    events: VecDeque<SessionMessage>,
    /// The local ENR.
    enr: Enr,
    /// The keypair to sign the ENR and set up encrypted communication with peers.
    keypair: Keypair,
    /// Pending raw requests. A list of raw messages we are awaiting a response from the remote
    /// for.
    pending_requests: FnvHashMap<AuthTag, Request>,
    /// Keep track of sent WHOAREYOU packets separately for quick searching.
    whoareyou_requests: FnvHashMap<NodeId, Request>,
    /// Pending messages. Messages awaiting to be sent, once a handshake has been established.
    pending_messages: FnvHashMap<NodeId, Vec<ProtocolMessage>>,
    /// Session keys. Established sessions for each NodeId.
    session_keys: FnvHashMap<NodeId, Session>,
    /// Heartbeat timer, used to to check for message and session timeouts.
    heartbeat: Interval,
    /// The discovery v5 UDP service.
    service: Discv5Service,
}

impl SessionService {
    /// A new Session service which instantiates the UDP socket and builds a local ENR to send to
    /// other nodes. This requires a `Keypair` to sign the ENR and set up encrypted sessions
    /// with other peers. The `tcp` parameter can be optionally given to add to the ENR record to
    /// alert other peers of a listening tcp port.
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
        let node_id = enr.node_id;
        let magic = {
            let mut hasher = Sha256::new();
            hasher.input(node_id);
            hasher.input(b"WHOAREYOU");
            let mut magic = [0u8; MAGIC_LENGTH];
            magic.copy_from_slice(&hasher.result());
            magic
        };

        Ok(SessionService {
            events: VecDeque::new(),
            enr,
            keypair,
            pending_requests: FnvHashMap::default(),
            whoareyou_requests: FnvHashMap::default(),
            pending_messages: FnvHashMap::default(),
            session_keys: FnvHashMap::default(),
            heartbeat: Interval::new(
                Instant::now() + Duration::from_secs(HEARTBEAT_INTERVAL),
                Duration::from_secs(HEARTBEAT_INTERVAL),
            ),
            service: Discv5Service::new(disc_socket_addr, magic)?,
        })
    }

    /// Sends a message to a node given the nodes ENR. This function will handle establishing a
    /// session and retrying requests on timeout.
    pub fn send_message(&mut self, dst_enr: &Enr, message: ProtocolMessage) {
        // check for an established session
        let dst_id = dst_enr.node_id;

        let dst = match dst_enr.socket() {
            Some(s) => s,
            None => {
                warn!("Could not send message. ENR has no ip/port: {}", dst_enr);
                return;
            }
        };

        let session = match self.session_keys.get(&dst_id) {
            Some(s) => s,
            None => {
                // check for pending WHOAREYOU request
                if !self.whoareyou_requests.get(&dst_id).is_some() {
                    debug!(
                        "No session established, sending a random packet to: {}",
                        hex::encode(dst_id)
                    );

                    // need to establish a new session, send a random packet
                    let random_data = (0..44).map(|_| rand::random::<u8>()).collect();
                    let auth_tag: AuthTag = rand::random();
                    let packet = Packet::RandomPacket {
                        tag: self.tag(&dst_id),
                        auth_tag: auth_tag.clone(),
                        data: Box::new(random_data),
                    };
                    self.send_packet(dst, dst_enr, packet, Some(&auth_tag));
                }
                // we are currently establishing a connection, add to pending messages
                debug!("Awaiting a session to established, caching message");
                let msgs = self
                    .pending_messages
                    .entry(dst_id)
                    .or_insert_with(|| Vec::new());
                msgs.push(message);
                return;
            }
        };

        // session is established, encrypt the message and send
        let tag = self.tag(&dst_id);
        let (cipher, auth_tag) =
            match crypto::encrypt_message(&session.encryption_key, None, &message.encode(), &tag) {
                Ok(c) => c,
                Err(_) => {
                    error!("Failed to encrypt message");
                    return;
                }
            };

        let packet = Packet::Message {
            tag,
            auth_tag,
            message: Box::new(cipher),
        };
        self.send_packet(dst, dst_enr, packet, Some(&auth_tag));
    }

    /// This is called in response to a SessionMessage::WhoAreYou event. The protocol finds the
    /// highest known ENR then calls this function to send a WHOAREYOU packet.
    pub fn send_whoareyou(&mut self, dst: SocketAddr, dst_enr: &Enr, auth_tag: AuthTag) {
        let dst_id = dst_enr.node_id;

        // check there is not already a WHOAREYOU packet already sent
        if self.whoareyou_requests.get(&dst_id).is_some() {
            warn!("WHOAREYOU packet already sent");
            return;
        }
        debug!("Sending WHOAREYOU packet to: {}", hex::encode(dst_id));

        let magic = {
            let mut hasher = Sha256::new();
            hasher.input(dst_id);
            hasher.input(b"WHOAREYOU");
            let mut magic = [0u8; MAGIC_LENGTH];
            magic.copy_from_slice(&hasher.result());
            magic
        };

        let id_nonce: Nonce = rand::random();

        let packet = Packet::WhoAreYou {
            tag: self.tag(&dst_id),
            magic,
            token: auth_tag,
            id_nonce,
            enr_seq: dst_enr.seq,
        };

        self.send_packet(dst, dst_enr, packet, None);
    }

    /// Calculates the src `NodeId` given a tag.
    fn src_id(&self, tag: &Tag) -> Tag {
        let hash = Sha256::digest(&self.enr.node_id);
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
            tag[i] = hash[i] ^ self.enr.node_id[i];
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
        // the auth-tag must match a pending request
        let req = match self.pending_requests.remove(&token) {
            Some(v) => v,
            None => {
                debug!("Received a WHOAREYOU packet that references an unknown or expired request");
                return;
            }
        };

        // the referenced request must come from the expected src or node-id
        if src != req.dst || src_id != req.enr.node_id {
            // add the request back
            self.pending_requests.insert(token, req);
            warn!("Incorrect WHOAREYOU packet source");
            return;
        }

        debug!("Received a WHOAREYOU packet from: {}", hex::encode(src_id));

        // get the messages that are waiting for an established session
        let messages = match self.pending_messages.get_mut(&src_id) {
            Some(v) => v,
            None => {
                // this should not happen
                error!("No pending messages found for WHOAREYOU request.");
                return;
            }
        };

        if messages.is_empty() {
            debug!("No pending messages found for WHOAREYOU request.");
            return;
        }

        // generate the session key for the node
        let (encryption_key, decryption_key, auth_resp_key, ephem_pubkey) =
            match crypto::generate_session_keys(&self.enr.node_id, &req.enr, &id_nonce) {
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
        let nonce = crypto::generate_nonce(id_nonce);
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
        debug!(
            "Sending Authentication response to node: {} at: {:?}",
            hex::encode(src_id),
            src
        );
        self.service.send(src, packet);

        // add the keys to memory with a timeout
        debug!("Session established with node: {}", hex::encode(src_id));
        let session = Session {
            encryption_key,
            decryption_key: decryption_key.clone(),
            timeout: Instant::now() + Duration::from_secs(SESSION_TIMEOUT),
        };
        self.session_keys.insert(src_id.clone(), session);

        // flush the message cache
        self.flush_messages(src, &src_id, &req.enr, &encryption_key);
    }

    // Processing logic for receiving a message containing an Authentication header
    fn handle_auth_message(
        &mut self,
        src: SocketAddr,
        tag: Tag,
        auth_header: AuthHeader,
        message: &[u8],
    ) {
        // Needs to match an outgoing WHOAREYOU packet (so we have the required nonce to be signed). If it doesn't we drop the packet. This will
        // lead to future outgoing WHOAREYOU packets if they proceed to send further encrypted
        // packets.
        let src_id = self.src_id(&tag);
        debug!(
            "Received an Authentication header message from: {}",
            hex::encode(src_id)
        );
        let req = self.whoareyou_requests.remove(&src_id);

        if req.is_none() {
            warn!("Received an authenticated header without a known WHOAREYOU packet. Dropping");
            return;
        }
        let req = req.expect("not empty");

        // verify the source ip, avoid spam and signature verification calculations from malicious packets.
        // the referenced request must come from the expected src or node-id
        if src != req.dst || src_id != req.enr.node_id {
            warn!("Received an authenticated header from incorrect source. Expected id: {:?}, actual id: {:?}, expected source: {:?} actual source: {:?}", req.enr.node_id, src_id, req.dst, src);
            // add the request back
            self.whoareyou_requests.insert(src_id.clone(), req);
            return;
        }

        // get the nonce
        let id_nonce = match req.packet {
            Packet::WhoAreYou { id_nonce, .. } => id_nonce,
            _ => unreachable!("Coding error if there is not a WHOAREYOU packet in this request"),
        };

        // obtain the session keys
        let (decryption_key, encryption_key, auth_resp_key) = match crypto::derive_keys_from_pubkey(
            &self.keypair,
            &self.enr.node_id,
            &req.enr.node_id,
            &id_nonce,
            &auth_header.ephemeral_pubkey,
        ) {
            Ok(v) => v,
            Err(e) => {
                warn!("Invalid Authentication header: {:?}", e);
                return;
            }
        };

        // verify the authentication header
        let updated_enr = match crypto::verify_authentication_header(
            &auth_resp_key,
            id_nonce,
            &auth_header,
            &self.tag(&src_id),
            &req.enr,
        ) {
            Ok(enr) => enr,
            Err(e) => {
                warn!("Invalid authentication header: {:?}", e);
                return;
            }
        };

        // add an event if we have an updated enr
        if let Some(enr) = updated_enr {
            self.events
                .push_back(SessionMessage::UpdatedEnr(Box::new(enr)));
        }

        // update the session keys
        let session = Session {
            encryption_key,
            decryption_key,
            timeout: Instant::now() + Duration::from_secs(SESSION_TIMEOUT),
        };
        self.session_keys.insert(src_id.clone(), session);

        // decrypt the message
        let mut aad = tag.to_vec();
        aad.append(&mut auth_header.encode());
        self.handle_message(src, src_id, auth_header.auth_tag, message, &aad);

        // flush messages awaiting a session
        self.flush_messages(src, &src_id, &req.enr, &encryption_key);
    }

    fn handle_message(
        &mut self,
        src: SocketAddr,
        src_id: NodeId,
        auth_tag: AuthTag,
        message: &[u8],
        aad: &[u8],
    ) {
        // check if we have an established session
        let session = match self.session_keys.get(&src_id) {
            Some(session) => session,
            None => {
                // no session exists
                // check if we are awaiting an auth packet
                debug!("Received a message without a session.");
                if self.whoareyou_requests.get(&src_id).is_some() {
                    debug!("Waiting for a session to be generated.");
                // potentially store and decrypt once we receive the packet.
                // drop it for now.
                } else {
                    debug!("Requesting a WHOAREYOU packet to be sent");
                    // spawn a WHOAREYOU event to check for highest known ENR
                    let event = SessionMessage::WhoAreYouRequest {
                        src,
                        src_id: src_id.clone(),
                        auth_tag,
                    };
                    self.events.push_back(event);
                }
                return;
            }
        };

        // we have a known session, decrypt and process the message
        let message = match crypto::decrypt_message(&session.decryption_key, auth_tag, message, aad)
        {
            Ok(m) => match ProtocolMessage::decode(m) {
                Ok(m) => m,
                Err(e) => {
                    warn!("Failed to decode message. Error: {:?}", e);
                    return;
                }
            },
            Err(e) => {
                debug!("Message from node: {:?} in not encrypted with known session keys. Requesting WHOAREYOU packet. Error: {:?}", hex::encode(src_id), e);
                // spawn a WHOAREYOU event to check for highest known ENR
                let event = SessionMessage::WhoAreYouRequest {
                    src,
                    src_id: src_id.clone(),
                    auth_tag,
                };
                self.events.push_back(event);
                return;
            }
        };

        // we have received a new message. Notify the protocol.
        debug!("Message received: {:?}", message);
        self.events
            .push_back(SessionMessage::Message(Box::new(message)));
    }

    // encrypts and sends any messages that were waiting for a session to be established
    // TODO: Fix this once fleshed out
    #[inline]
    fn flush_messages(&mut self, dst: SocketAddr, dst_id: &NodeId, enr: &Enr, key: &[u8; 16]) {
        let tag = self.tag(&dst_id);

        let mut messages = match self.pending_messages.remove(dst_id) {
            Some(v) => v,
            None => {
                return;
            }
        };
        for _ in 0..messages.len() {
            let msg = messages.remove(0);
            let (cipher, auth_tag) = match crypto::encrypt_message(key, None, &msg.encode(), &tag) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to encrypt message, Error: {:?}", e);
                    return;
                }
            };
            let packet = Packet::Message {
                tag,
                auth_tag,
                message: Box::new(cipher.clone()),
            };
            debug!("Sending cached message");
            self.send_packet(dst, enr, packet, Some(&auth_tag));
        }
    }

    // wrapper around service.send() that adds all sent messages to the pending_requests hashmap
    #[inline]
    fn send_packet(
        &mut self,
        dst: SocketAddr,
        dst_enr: &Enr,
        packet: Packet,
        auth_tag: Option<&AuthTag>,
    ) {
        self.service.send(dst, packet.clone());
        let dst_id = dst_enr.node_id;
        let request = Request {
            dst,
            enr: dst_enr.clone(),
            packet,
            timeout: Instant::now() + Duration::from_secs(REQUEST_TIMEOUT),
            retries: 1,
        };

        match &request.packet {
            Packet::WhoAreYou { .. } => self.whoareyou_requests.insert(dst_id, request),
            _ => self.pending_requests.insert(
                auth_tag.expect("Programming Error if this is None").clone(),
                request,
            ),
        };
    }

    fn heartbeat(&mut self) {
        // remove expired requests/sessions
        self.pending_requests
            .retain(|_, req| req.timeout >= Instant::now() || req.retries < REQUEST_RETRIES);
        self.session_keys
            .retain(|_, session| session.timeout <= Instant::now());

        // resend requests
        for req in self
            .pending_requests
            .values_mut()
            .filter(|v| v.timeout < Instant::now())
        {
            debug!("Resending message to {:?}", hex::encode(req.enr.node_id));
            self.service.send(req.dst, req.packet.clone());
            req.retries += 1;
        }
    }

    pub fn poll(&mut self) -> Async<SessionMessage> {
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
                            self.handle_auth_message(src, tag, auth_header, &message);
                        }
                        Packet::Message {
                            tag,
                            auth_tag,
                            message,
                        } => {
                            let src_id = self.src_id(&tag);
                            self.handle_message(src, src_id, auth_tag, &message, &tag);
                        }
                        Packet::RandomPacket { .. } => {} // this will not be decoded.
                    }
                }
                Async::NotReady => break,
            }
        }

        // process any events if necessary
        if let Some(event) = self.events.pop_front() {
            return Async::Ready(event);
        }

        // check for timeouts
        loop {
            match self.heartbeat.poll() {
                Ok(Async::Ready(_)) => {
                    self.heartbeat();
                }
                Ok(Async::NotReady) => {
                    break;
                }
                _ => {
                    panic!("Discv5 heartbeat has ended");
                }
            }
        }

        Async::NotReady
    }
}

#[derive(Debug)]
pub enum SessionMessage {
    Message(Box<ProtocolMessage>),
    UpdatedEnr(Box<Enr>),
    WhoAreYouRequest {
        src: SocketAddr,
        src_id: NodeId,
        auth_tag: AuthTag,
    },
}

#[derive(Debug, Clone)]
pub struct Request {
    pub dst: SocketAddr,
    pub enr: Enr,
    pub packet: Packet,
    pub timeout: Instant,
    pub retries: u8,
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
