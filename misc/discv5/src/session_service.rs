//! Session management for the Discv5 Discovery service.
//!
//! The `SessionService` is responsible for establishing and maintaining sessions with
//! connected/discovered nodes. Each node, identified by it's [`NodeId`] is associated with a
//! [`Session`]. This service drives the handshakes for establishing the sessions and associated
//! logic for sending/requesting initial connections/ENR's from unknown peers.
//!
//! The `SessionService` also manages the timeouts for each request and reports back RPC failures,
//! session timeouts and received messages. Messages are encrypted and decrypted using the
//! associated `Session` for each node.
//!
//TODO: Document the Event structure and WHOAREYOU requests to the protocol layer.

use super::packet::{AuthHeader, AuthResponse, AuthTag, Magic, Nonce, Packet, Tag, TAG_LENGTH};
use super::service::Discv5Service;
use crate::error::Discv5Error;
use crate::rpc::{ProtocolMessage, RpcType};
use crate::session::{Session, SessionStatus};
use enr::{Enr, NodeId};
use fnv::FnvHashMap;
use futures::prelude::*;
use libp2p_core::identity::Keypair;
use log::{debug, error, trace, warn};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::default::Default;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::timer::Delay;

mod tests;

/// Seconds before a timeout expires.
const REQUEST_TIMEOUT: u64 = 10;
/// The number of times to retry a request.
const REQUEST_RETRIES: u8 = 2;
pub const SESSION_TIMEOUT: u64 = 30;

pub struct SessionService {
    /// Queue of events produced by the session service.
    events: VecDeque<SessionEvent>,

    /// The local ENR.
    enr: Enr,

    /// The keypair to sign the ENR and set up encrypted communication with peers.
    keypair: Keypair,

    /// Pending raw requests. A list of raw messages we are awaiting a response from the remote
    /// for.
    pending_requests: FnvHashMap<NodeId, Vec<Request>>,

    /// Sent WHOAREYOU messages. Stored separately to lookup via `NodeId`.
    whoareyou_requests: FnvHashMap<NodeId, Request>,

    /// Pending messages. Messages awaiting to be sent, once a handshake has been established.
    pending_messages: FnvHashMap<NodeId, Vec<ProtocolMessage>>,

    /// Sessions that have been created for each node id. These can be established or
    /// awaiting response from remote nodes.
    //TODO: Limit number of sessions
    sessions: FnvHashMap<NodeId, Session>,

    /// The discovery v5 UDP service.
    service: Discv5Service,
}

impl SessionService {
    /// A new Session service which instantiates the UDP socket.
    pub fn new(enr: Enr, keypair: Keypair) -> io::Result<Self> {
        // ensure the keypair matches the one that signed the enr.
        if enr.public_key().into_protobuf_encoding() != keypair.public().into_protobuf_encoding() {
            panic!("Discv5: Provided keypair does not match the provided ENR keypair");
        }

        let udp = enr.udp().unwrap_or_else(|| 9000);
        let ip = enr
            .ip()
            .unwrap_or_else(|| "127.0.0.1".parse().expect("valid IP"));

        let socket_addr = SocketAddr::new(ip, udp);
        // generates the WHOAREYOU magic packet for the local node-id
        let magic = {
            let mut hasher = Sha256::new();
            hasher.input(enr.node_id().raw());
            hasher.input(b"WHOAREYOU");
            let mut magic: Magic = Default::default();
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
            sessions: FnvHashMap::default(),
            service: Discv5Service::new(socket_addr, magic)?,
        })
    }

    /// Sends a message to a node given the node's ENR. This function will handle establishing a
    /// session and retrying requests on timeout. An optional SocketAddr can be provided to
    /// override sending the packet based on the node's ENR.
    pub fn send_message(
        &mut self,
        dst_enr: &Enr,
        message: ProtocolMessage,
        socket_addr: Option<SocketAddr>,
    ) -> Result<(), Discv5Error> {
        // check for an established session
        let dst_id = dst_enr.node_id();

        let dst = {
            if let Some(socket) = socket_addr {
                socket
            } else {
                dst_enr.udp_socket().ok_or_else(|| {
                    warn!(
                        "Could not send message. ENR doesn't contain an IP and UDP port: {}",
                        dst_enr
                    );
                    Discv5Error::InvalidEnr
                })?
            }
        };

        let session = match self.sessions.get(dst_id) {
            Some(s) if s.established() => s,
            Some(_) => {
                // we are currently establishing a connection, add to pending messages
                debug!("Awaiting a session to established, caching message");
                let msgs = self
                    .pending_messages
                    .entry(dst_id.clone())
                    .or_insert_with(Vec::new);
                msgs.push(message);
                return Ok(());
            }
            None => {
                debug!(
                    "No session established, sending a random packet to: {}",
                    dst_id
                );
                // cache message
                let msgs = self
                    .pending_messages
                    .entry(dst_id.clone())
                    .or_insert_with(Vec::new);
                msgs.push(message);

                // need to establish a new session, send a random packet
                let (session, packet) = Session::new_random(self.tag(&dst_id), dst_enr.clone());

                let request = Request::new(dst, packet, None);

                self.send_request(dst_id.clone(), request);
                self.sessions.insert(dst_id.clone(), session);
                return Ok(());
            }
        };

        // session is established, encrypt the message and send
        let packet = session
            .encrypt_message(self.tag(&dst_id), &message.clone().encode())
            .map_err(|e| {
                error!("Failed to encrypt message");
                e
            })?;

        // only log the packet request if it's an RPC request
        if let RpcType::Request(_) = &message.body {
            let request = Request::new(dst, packet, Some(message));
            self.send_request(dst_id.clone(), request);
        } else {
            // send the response
            self.service.send(dst, packet);
        }

        Ok(())
    }

    /// This is called in response to a SessionMessage::WhoAreYou event. The protocol finds the
    /// highest known ENR then calls this function to send a WHOAREYOU packet.
    //TODO: Create a more elegant API
    pub fn send_whoareyou(
        &mut self,
        dst: SocketAddr,
        node_id: &NodeId,
        enr_seq: u64,
        remote_enr: Option<Enr>,
        auth_tag: AuthTag,
    ) {
        // If a WHOAREYOU is already sent or a session is already established, ignore this request.
        match self.sessions.get(node_id) {
            Some(s) if s.established() || s.status() == SessionStatus::WhoAreYouSent => {
                warn!("Session exists. WhoAreYou packet not sent");
                return;
            }
            _ => {}
        }

        debug!("Sending WHOAREYOU packet to: {}", node_id);
        let (session, packet) =
            Session::new_whoareyou(self.tag(node_id), node_id, enr_seq, remote_enr, auth_tag);
        self.sessions.insert(node_id.clone(), session);
        let request = Request::new(dst, packet, None);
        self.send_request(node_id.clone(), request);
    }

    /// Calculates the src `NodeId` given a tag.
    fn src_id(&self, tag: &Tag) -> NodeId {
        let hash = Sha256::digest(&self.enr.node_id().raw());
        let mut src_id: [u8; 32] = Default::default();
        for i in 0..32 {
            src_id[i] = hash[i] ^ tag[i];
        }
        NodeId::new(&src_id)
    }

    /// Calculates the tag given a `NodeId`.
    fn tag(&self, dst_id: &NodeId) -> Tag {
        let hash = Sha256::digest(&dst_id.raw());
        let mut tag: Tag = Default::default();
        for i in 0..TAG_LENGTH {
            tag[i] = hash[i] ^ self.enr.node_id().raw()[i];
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
    ) -> Result<(), ()> {
        // the auth-tag must match a pending request
        let req = {
            if let Some(known_reqs) = self.pending_requests.get_mut(&src_id) {
                if let Some(pos) = known_reqs
                    .iter()
                    .position(|req| req.packet.auth_tag() == Some(&token))
                {
                    Some(known_reqs.remove(pos))
                } else {
                    None
                }
            } else {
                None
            }
        };
        let req = req.ok_or_else(|| {
            debug!("Received a WHOAREYOU packet that references an unknown or expired request");
        })?;

        // the referenced request must come from the expected src
        if src != req.dst {
            // add the request back - order is unimportant
            self.pending_requests
                .entry(src_id)
                .or_insert_with(Vec::new)
                .push(req);
            warn!("Incorrect WHOAREYOU packet source");
            return Err(());
        }

        debug!("Received a WHOAREYOU packet from: {}", src_id);

        let tag = self.tag(&src_id);

        // find the session associated with this WHOAREYOU
        let session = self.sessions.get_mut(&src_id).ok_or_else(|| {
            warn!("Received a WHOAREYOU packet without having an established session.")
        })?;

        // Determine which message to send back. A WHOAREYOU could refer to the random packet
        // sent during an establishing a connection, or their session has expired on one of our
        // sent messages and we need to re-encrypt it.
        let message = {
            if let Packet::RandomPacket { .. } = req.packet {
                // get the messages that are waiting for an established session
                let messages = self
                    .pending_messages
                    .get_mut(&src_id)
                    .ok_or_else(|| error!("No pending messages found for WHOAREYOU request."))?;

                if messages.is_empty() {
                    debug!("No pending messages found for WHOAREYOU request.");
                    return Err(());
                }
                // select the first message in the queue
                messages.remove(0)
            } else {
                // re-send the original message
                req.message
                    .expect("All non-random requests must have an unencrypted message")
            }
        };

        // sign the nonce
        let nonce = Session::generate_nonce(id_nonce);
        let sig = self.keypair.sign(&nonce).map_err(|e| {
            error!(
                "Error signing WHOAREYOU Nonce. Ignoring  WHOAREYOU packet. Error: {:?}",
                e
            )
        })?;

        // update the enr record if we need need to
        let updated_enr = if enr_seq < self.enr.seq {
            Some(self.enr.clone())
        } else {
            None
        };

        // generate the auth response to be encrypted
        let auth_pt = AuthResponse::new(&sig, updated_enr).encode();

        // generate session keys and encrypt the earliest packet with the authentication header
        let auth_packet = match session.encrypt_with_header(
            tag,
            &self.enr.node_id(),
            &id_nonce,
            &auth_pt,
            &message.clone().encode(),
        ) {
            Ok(p) => p,
            Err(e) => {
                // insert the message back into the pending queue
                self.pending_messages
                    .entry(src_id)
                    .or_insert_with(Vec::new)
                    .insert(0, message);
                error!("Could not generate a session. Error: {:?}", e);
                return Err(());
            }
        };

        debug!("Session established with node: {}", src_id);
        // session has been established, notify the protocol

        self.events.push_back(SessionEvent::Established(
            src_id.clone(),
            session
                .remote_enr()
                .clone()
                .expect("ENR exists when awaiting a WHOAREYOU"),
        ));
        // send the response
        let request = Request::new(src, auth_packet, Some(message));
        debug!("Sending Authentication response to node: {}", src_id);
        self.send_request(src_id.clone(), request);

        // flush the message cache
        let _ = self.flush_messages(src, &src_id);
        Ok(())
    }

    /// Handle a message that contains an authentication header.
    fn handle_auth_message(
        &mut self,
        src: SocketAddr,
        tag: Tag,
        auth_header: AuthHeader,
        message: &[u8],
    ) -> Result<(), ()> {
        // Needs to match an outgoing WHOAREYOU packet (so we have the required nonce to be signed). If it doesn't we drop the packet. This will
        // lead to future outgoing WHOAREYOU packets if they proceed to send further encrypted
        // packets.
        let src_id = self.src_id(&tag);
        debug!("Received an Authentication header message from: {}", src_id);

        let session = self.sessions.get_mut(&src_id).ok_or_else(|| {
            warn!("Received an authenticated header without a known session. Dropping")
        })?;

        // check that we are awaiting a response for a WHOAREYOU message
        if session.status() != SessionStatus::WhoAreYouSent {
            warn!("Received an authenticated header without a known WHOAREYOU session. Dropping");
            return Err(());
        }

        let req = self
            .whoareyou_requests
            .remove(&src_id)
            .ok_or_else(|| error!("There was no WHOAREYOU request associated with a session"))?;

        // verify the source ip, avoid spam and signature verification calculations from malicious packets.
        // the referenced request must come from the expected src
        if src != req.dst {
            warn!("Received an authenticated header from incorrect source. NodeId: {}, expected source: {:?} actual source: {:?}", src_id, req.dst, src);
            // add the request back
            self.whoareyou_requests.insert(src_id, req);
            return Err(());
        }

        // get the nonce
        let id_nonce = match req.packet {
            Packet::WhoAreYou { id_nonce, .. } => id_nonce,
            _ => unreachable!("Coding error if there is not a WHOAREYOU packet in this request"),
        };

        match session.generate_keys_from_header(
            tag,
            &self.keypair,
            &self.enr.node_id(),
            &src_id,
            id_nonce,
            &auth_header,
        ) {
            Ok(_) => {}
            Err(e) => {
                warn!(
                    "Invalid Authentication header. Dropping session. Error: {:?}",
                    e
                );
                self.sessions.remove(&src_id);
                self.pending_messages.remove(&src_id);
                return Err(());
            }
        }

        debug!("Session established with node: {}", src_id);
        // session has been established, notify the protocol
        self.events.push_back(SessionEvent::Established(
            src_id.clone(),
            session
                .remote_enr()
                .clone()
                .expect("ENR exists when awaiting a WHOAREYOU"),
        ));

        // decrypt the message
        let mut aad = tag.to_vec();
        aad.append(&mut auth_header.encode());
        // log and continue on error
        let _ = self.handle_message(src, src_id.clone(), auth_header.auth_tag, message, &aad);

        // flush messages awaiting a session
        let _ = self.flush_messages(src, &src_id);
        Ok(())
    }

    /// Handle a standard message that does not contain an authentication header.
    fn handle_message(
        &mut self,
        src: SocketAddr,
        src_id: NodeId,
        auth_tag: AuthTag,
        message: &[u8],
        aad: &[u8],
    ) -> Result<(), ()> {
        // check if we have an established session
        let session = match self.sessions.get(&src_id) {
            Some(s) if s.established() => s,
            Some(s) => {
                // if we have sent a random packet, upgrade to a WhoAreYou request
                if s.status() == SessionStatus::RandomSent {
                    let event = SessionEvent::WhoAreYouRequest {
                        src,
                        src_id: src_id.clone(),
                        auth_tag,
                    };
                    self.events.push_back(event);
                } else {
                    debug!("Waiting for a session to be generated.");
                    // potentially store and decrypt once we receive the packet.
                    // drop it for now.
                }
                return Ok(());
            }
            None => {
                // no session exists
                debug!("Received a message without a session. From: {}", src_id);
                debug!("Requesting a WHOAREYOU packet to be sent.");
                // spawn a WHOAREYOU event to check for highest known ENR
                let event = SessionEvent::WhoAreYouRequest {
                    src,
                    src_id: src_id.clone(),
                    auth_tag,
                };
                self.events.push_back(event);
                return Ok(());
            }
        };

        // we have a known session, decrypt and process the message
        let message = match session.decrypt_message(auth_tag, message, aad) {
            Ok(m) => ProtocolMessage::decode(m)
                .map_err(|e| warn!("Failed to decode message. Error: {:?}", e))?,
            Err(e) => {
                debug!("Message from node: {} in not encrypted with known session keys. Requesting WHOAREYOU packet. Error: {:?}", src_id, e);
                // spawn a WHOAREYOU event to check for highest known ENR
                let event = SessionEvent::WhoAreYouRequest {
                    src,
                    src_id: src_id.clone(),
                    auth_tag,
                };
                self.events.push_back(event);
                return Err(());
            }
        };

        // Remove any associated request from pending_request
        if let Some(known_reqs) = self.pending_requests.get_mut(&src_id) {
            if let Some(pos) = known_reqs
                .iter()
                .position(|req| req.id() == Some(message.id))
            {
                trace!("Removing request id: {}", message.id);
                known_reqs.remove(pos);
            }
        }

        // we have received a new message. Notify the behaviour.
        debug!("Message received: {}", message);
        let event = SessionEvent::Message {
            src_id,
            src,
            message: Box::new(message),
        };
        self.events.push_back(event);
        Ok(())
    }

    /// Encrypts and sends any messages that were waiting for a session to be established.
    #[inline]
    fn flush_messages(&mut self, dst: SocketAddr, dst_id: &NodeId) -> Result<(), ()> {
        let mut requests_to_send = Vec::new();

        {
            // get the session for this id
            let session = match self.sessions.get(dst_id) {
                Some(s) if s.established() => s,
                _ => {
                    // no session
                    return Err(());
                }
            };

            let tag = self.tag(dst_id);

            let messages = self
                .pending_messages
                .remove(dst_id)
                .ok_or_else(|| trace!("No messages to send"))?;

            for msg in messages.into_iter() {
                let packet = session
                    .encrypt_message(tag, &msg.clone().encode())
                    .map_err(|e| warn!("Failed to encrypt message, Error: {:?}", e))?;
                let request = Request::new(dst, packet, Some(msg));
                requests_to_send.push(request);
            }
        }

        for request in requests_to_send.into_iter() {
            debug!("Sending cached message");
            self.send_request(dst_id.clone(), request);
        }
        Ok(())
    }

    /// Wrapper around `service.send()` that adds all sent messages to the `pending_requests`.
    #[inline]
    fn send_request(&mut self, node_id: NodeId, request: Request) {
        self.service.send(request.dst, request.packet.clone());

        match &request.packet {
            Packet::WhoAreYou { .. } => {
                self.whoareyou_requests.insert(node_id, request);
            }
            _ => {
                self.pending_requests
                    .entry(node_id)
                    .or_insert_with(Vec::new)
                    .push(request);
            }
        }
    }

    /// The heartbeat which checks for timeouts and reports back failed RPC requests/sessions.
    fn check_timeouts(&mut self) {
        // remove expired requests/sessions
        // log pending request timeouts
        for (node_id, requests) in self.pending_requests.iter_mut() {
            let mut expired_requests = Vec::new();
            for (pos, req) in requests.iter_mut().enumerate() {
                match req.timeout.poll() {
                    Ok(Async::Ready(_)) => {
                        if req.retries >= REQUEST_RETRIES {
                            // the RPC has expired
                            // determine which kind of RPC has timed out
                            match req.packet {
                                Packet::RandomPacket { .. } => {
                                    // no response from peer, flush all pending messages
                                    if let Some(pending_messages) =
                                        self.pending_messages.remove(&node_id)
                                    {
                                        for msg in pending_messages {
                                            self.events.push_back(SessionEvent::RequestFailed(
                                                node_id.clone(),
                                                msg.id,
                                            ));
                                        }
                                    }
                                    // drop the session
                                    debug!(
                                        "Session couldn't be established with Node: {}",
                                        node_id
                                    );
                                    self.sessions.remove(&node_id);
                                }
                                Packet::AuthMessage { .. } | Packet::Message { .. } => {
                                    self.events.push_back(SessionEvent::RequestFailed(
                                        node_id.clone(),
                                        req.id().expect("Auth messages have an rpc id"),
                                    ));
                                }
                                Packet::WhoAreYou { .. } => {
                                    unreachable!("WHOAREYOU requests are not in requests")
                                }
                            }
                            expired_requests.push(pos);
                        } else {
                            // increment the request retry count and restart the timeout
                            debug!("Resending message: {:?} to node: {}", req.packet, node_id);
                            self.service.send(req.dst, req.packet.clone());
                            req.retries += 1;
                            req.timeout =
                                Delay::new(Instant::now() + Duration::from_secs(REQUEST_TIMEOUT));
                        }
                    }
                    Ok(Async::NotReady) => (),
                    Err(_) => (),
                }
            }
            // remove any requests that have expired
            for expired in expired_requests {
                requests.remove(expired);
            }
        }

        let mut to_remove_reqs = Vec::new();
        for (node_id, req) in self.whoareyou_requests.iter_mut() {
            match req.timeout.poll() {
                Ok(Async::Ready(_)) => {
                    if req.retries >= REQUEST_RETRIES {
                        to_remove_reqs.push(node_id.clone());
                        if let Some(pending_messages) = self.pending_messages.remove(node_id) {
                            for msg in pending_messages {
                                self.events.push_back(SessionEvent::RequestFailed(
                                    node_id.clone(),
                                    msg.id,
                                ));
                            }
                        }
                    } else {
                        debug!(
                            "Resending WHOAREYOU message. Iteration: {},  NodeId: {}",
                            req.retries, node_id
                        );
                        self.service.send(req.dst, req.packet.clone());
                        req.retries += 1;
                        req.timeout =
                            Delay::new(Instant::now() + Duration::from_secs(REQUEST_TIMEOUT));
                    }
                }
                Ok(Async::NotReady) => (),
                Err(_) => (),
            }
        }

        for id in to_remove_reqs.into_iter() {
            self.whoareyou_requests.remove(&id);
        }

        // remove timed-out sessions - do not need to alert the protocol
        // Only drop a session if we are not expecting any responses.
        let mut to_remove_sessions = Vec::new();
        for (node_id, session) in self.sessions.iter_mut() {
            if let Some(timeout) = session.timeout() {
                match timeout.poll() {
                    Ok(Async::Ready(_)) => {
                        // only remove a session if there are no pending requests.
                        let reqs = self.pending_requests.get(&node_id);
                        let whos = self.whoareyou_requests.get(&node_id);
                        if reqs.map_or(true, |v| v.is_empty()) && whos.is_none() {
                            session.increment_timeout(REQUEST_TIMEOUT);
                        } else {
                            debug!("Session timed out for node: {}", node_id);
                            to_remove_sessions.push(node_id.clone());
                        }
                    }
                    Ok(Async::NotReady) => (),
                    Err(_) => (),
                }
            }
        }

        for id in to_remove_sessions.into_iter() {
            self.sessions.remove(&id);
        }
    }

    pub fn poll(&mut self) -> Async<SessionEvent> {
        loop {
            // process any events if necessary
            if let Some(event) = self.events.pop_front() {
                return Async::Ready(event);
            }

            // poll the discv5 service
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
                            let _ = self.handle_whoareyou(src, src_id, token, id_nonce, enr_seq);
                        }
                        Packet::AuthMessage {
                            tag,
                            auth_header,
                            message,
                        } => {
                            let _ = self.handle_auth_message(src, tag, auth_header, &message);
                        }
                        Packet::Message {
                            tag,
                            auth_tag,
                            message,
                        } => {
                            let src_id = self.src_id(&tag);
                            let _ = self.handle_message(src, src_id, auth_tag, &message, &tag);
                        }
                        Packet::RandomPacket { .. } => {} // this will not be decoded.
                    }
                }
                Async::NotReady => break,
            }
        }

        // check for timeouts
        self.check_timeouts();
        Async::NotReady
    }
}

#[derive(Debug)]
/// The output from polling the `SessionSerivce`.
pub enum SessionEvent {
    /// A session has been established with a node.
    Established(NodeId, Enr),

    /// A message was received.
    Message {
        src_id: NodeId,
        src: SocketAddr,
        message: Box<ProtocolMessage>,
    },

    /// A WHOAREYOU packet needs to be sent. This requests the protocol layer to send back the
    /// highest known ENR.
    WhoAreYouRequest {
        src: SocketAddr,
        src_id: NodeId,
        auth_tag: AuthTag,
    },

    /// An RPC request failed. The parameters are NodeId and the RPC-ID associated with the
    /// request.
    RequestFailed(NodeId, u64),
}

#[derive(Debug)]
/// A request to a node that we are waiting for a response.
pub struct Request {
    /// The destination socket address.
    pub dst: SocketAddr,

    /// The raw discv5 packet sent.
    pub packet: Packet,

    /// The un-encrypted message. Required if need to re-encrypt and re-send.
    pub message: Option<ProtocolMessage>,

    /// The time when this request times out.
    pub timeout: Delay,

    /// The number of times to re-send this request until it is considered failed.
    pub retries: u8,
}

impl Request {
    pub fn new(dst: SocketAddr, packet: Packet, message: Option<ProtocolMessage>) -> Self {
        Request {
            dst,
            packet,
            message,
            timeout: Delay::new(Instant::now() + Duration::from_secs(REQUEST_TIMEOUT)),
            retries: 1,
        }
    }

    pub fn id(&self) -> Option<u64> {
        self.message.as_ref().map(|m| m.id)
    }
}
