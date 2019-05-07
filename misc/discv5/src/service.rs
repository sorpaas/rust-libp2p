//! This starts a discv5 UDP service connection which handles discovery of peers and manages topics
//! and their advertisements as described by the [discv5
//! specification](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md).

use std::io;
use std::net;
use tokio_udp::UdpSocket;

const MAX_PACKET_SIZE: usize = 1280;

/// The main service that handles the UDP sockets and discv5 logic.
pub struct Discv5Service {
    /// The UDP socket for interacting over UDP.
    socket: UdpSocket,
    /// The buffer to accept inbound datagrams.
    recv_buffer: [u8; MAX_PACKET_SIZE],
}

impl Default for Discv5Service {
    fn default() -> Self {
        let default_addr: net::SocketAddr =
            "0.0.0.0:30303".parse().expect("This is a valid SocketAddr");
        Discv5Service::new(default_addr).unwrap() // bail on error.
    }
}

impl Discv5Service {
    pub fn new(socket_addr: net::SocketAddr) -> io::Result<Self> {
        // set up the UDP socket
        let socket = UdpSocket::bind(&socket_addr)?;

        Ok(Discv5Service {
            socket,
            recv_buffer: [0; MAX_PACKET_SIZE],
        })
    }

    /*
    pub fn poll(&mut self) -> Async<Discv5Message> {

            // query

            // send

            // incoming

            /*
            match self.socket.poll_recv_from(&mut self.recv_buffer) {
                Ok(Async::Ready((length, source))) => {
                }
            }
            */

    }
    */
}
