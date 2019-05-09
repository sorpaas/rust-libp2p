//! This starts a discv5 UDP service connection which handles discovery of peers and manages topics
//! and their advertisements as described by the [discv5
//! specification](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md).

use std::io;
use std::net;
use tokio_udp::UdpSocket;
use sha2::{Digest, Sha256};
use super::packet::{Packet,TAG_LENGTH, MAGIC_LENGTH, Tag};
use futures::prelude::*;

const MAX_PACKET_SIZE: usize = 1280;

/// The main service that handles the UDP sockets and discv5 logic.
pub struct Discv5Service {
    /// The UDP socket for interacting over UDP.
    socket: UdpSocket,
    /// The buffer to accept inbound datagrams.
    recv_buffer: [u8; MAX_PACKET_SIZE],
    /// The local enr. 
    enr: Enr,
    /// WhoAreYou Magic Value
    whoareyou_magic: [u8; MAGIC_LENGTH],
}

impl Default for Discv5Service {
    fn default() -> Self {
        let default_addr: net::SocketAddr =
            "0.0.0.0:30303".parse().expect("This is a valid SocketAddr");
        // TODO: Place-holder - remove later
        let default_id: [u8; TAG_LENGTH] = [0; TAG_LENGTH];
        Discv5Service::new(default_addr, default_id).unwrap() // bail on error.
    }
}

impl Discv5Service {
    pub fn new(socket_addr: net::SocketAddr, node_id: [u8;TAG_LENGTH]) -> io::Result<Self> {
        // set up the UDP socket
        let socket = UdpSocket::bind(&socket_addr)?;
        // calculate the WHOAREYOU you magic packet
        let whoareyou_magic = { 
            let hasher = Sha256::new();
            hasher.input(node_id.clone());
            hasher.input(b"WHOAREYOU");
            let mut magic: [u8; MAGIC_LENGTH] = [0; MAGIC_LENGTH];
            magic.copy_from_slice(&hasher.result());
            magic
        };

        Ok(Discv5Service {
            socket,
            recv_buffer: [0; MAX_PACKET_SIZE],
            node_id,
            whoareyou_magic,
        })
    }

    pub fn poll(&mut self) -> Async<Discv5Message> {

            // query

            // send


        // handle incoming messages
        loop {
            match self.socket.poll_recv_from(&mut self.recv_buffer) {
                Ok(Async::Ready((length, src))) => {
                    match Packet::decode(&self.recv_buffer[..length], &self.whoareyou_magic) {
                        Ok(Packet::WhoAreYou {tag, token, id_nonce, enr_seq, ..} =>  {
                            let src_id = self.get_source_id(tag);
                            self.handle_whoareyou(src, src_id, token, id_nonce, enr_seq);
                            break;
                        }
                        Ok(Packet::AuthMessage {tag, auth_header, message } =>  {
                            let src_id = self.get_source_id(tag);
                            self.handle_auth_message(src, src_id, auth_header, message);
                            break;
                        }
                        Ok(Packet::Message {tag, auth_tag, message} =>  {
                            let src_id = self.get_source_id(tag);
                            self.handle_message(src, src_id, auth_tag, message);
                            break;
                        }
                        Err(_) => { // could not decode the packet, drop it
                            break;
                        }
                }


                }
            }

            }

        }


            }
        }
    }



    fn get_source_id(&self, tag: Tag) -> [u8; TAG_LENGTH]  {
        let mut hasher = Sha256::new();
        hasher.input(self.node_id);
        let hash = hasher.result();
        let mut src_id: [u8; TAG_LENGTH] = [0; TAG_LENGTH];

        for i in 0..TAG_LENGTH {
            src_id[i] = hash[i] ^ tag[i];
        }

        src_id
}
