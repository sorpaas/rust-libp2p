use super::packet::{AuthTag, NodeId, Nonce, Packet, Tag, MAGIC_LENGTH, TAG_LENGTH};
use super::service::Discv5Service;
use enr::{Enr, EnrBuilder};
use futures::prelude::*;
use libp2p_core::identity::Keypair;
use log::{debug, warn};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
    /// Pending requests. Maps the authentication tag to ttl instant.
    pending_requests: HashMap<AuthTag, Request>,
    /// Session keys. Sessions are based on (IP, Node-Id)
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
            session_keys: HashMap::new(),
            service: Discv5Service::new(disc_socket_addr, magic)?,
        })
    }

    /// Calculates the src `NodeId` given a tag.
    fn get_src_id(&self, tag: Tag) -> Tag {
        let hash = Sha256::digest(&self.node_id);
        let mut src_id: Tag = [0; TAG_LENGTH];
        for i in 0..TAG_LENGTH {
            src_id[i] = hash[i] ^ tag[i];
        }
        src_id
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

        // generate the session key for the node
        //let session_key = handshake::generate(&req.enr, id_nonce);
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
                            let src_id = self.get_src_id(tag);
                            self.handle_whoareyou(src, src_id, token, id_nonce, enr_seq);
                        }
                        Packet::AuthMessage {
                            tag,
                            auth_header,
                            message,
                        } => {
                            let src_id = self.get_src_id(tag);
                            //    self.handle_auth_message(src, src_id, auth_header, message);
                        }
                        Packet::Message {
                            tag,
                            auth_tag,
                            message,
                        } => {
                            let src_id = self.get_src_id(tag);
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

pub struct Discv5Message {}

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
