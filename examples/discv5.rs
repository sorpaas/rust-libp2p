//! Demonstrates how to run a basic Discovery v5 Service.
//!
//! This example creates a libp2p discv5 service which searches for peers every 30 seconds. On
//! creation, the local ENR created for this service is displayed in base64. This can be
//! used to allow other instances to connect and join the network. The service can be stopped
//! by pressing Ctrl-C.
//!
//! To add peers to the network, create multiple instances of this service adding the ENR of a
//! participating node in the command line. The nodes should discover each other over a period
//! of time. (It is probabilistic that nodes to find each other on any given query).
//!
//! A single instance listening on a udp socket `127.0.0.1:9000` can be created via:
//!
//! ```sh
//! cargo run --example discv5
//! ```
//!
//! This will display the created ENR record for the node.
//!
//! An IP address, port and ENR node can also be passed as command line options.
//!
//! More specifically,
//!
//! ```sh
//! cargo run --example discv5 -- 127.0.0.1 9001 <Base64-ENR>
//! ```
//!
//! Therefore, a second instance, in a new terminal, can be run on port 9001 and connected to the first via:
//!
//! ```sh
//! cargo run --example discv5 -- 127.0.0.1 9001 <Base64-ENR>
//! ```
//!
//! where `<Base64-ENR>` is the base64 ENR given from executing the first node. These steps can be
//! repeated to add further nodes to the network.

use futures::prelude::*;
use libp2p::discv5::Discv5Event;
use libp2p::identity;
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::time::Duration;

fn main() {
    env_logger::init();

    // if there is an address specified use it
    let address = {
        if let Some(address) = std::env::args().nth(1) {
            address.parse::<Ipv4Addr>().unwrap()
        } else {
            "127.0.0.1".parse::<Ipv4Addr>().unwrap()
        }
    };

    let port = {
        if let Some(udp_port) = std::env::args().nth(2) {
            u16::from_str_radix(&udp_port, 10).unwrap()
        } else {
            9000
        }
    };

    // generate a key for the node
    let keypair = identity::Keypair::generate_secp256k1();
    // construct a local ENR
    let enr = libp2p::enr::EnrBuilder::new()
        .ip(address.into())
        .udp(port)
        .build(&keypair)
        .unwrap();

    println!("Base64 ENR: {}", enr.to_base64());

    // unused transport for building a swarm
    let transport = libp2p::build_development_transport(keypair.clone());

    // construct the discv5 swarm, initializing an unused transport layer
    let discv5 = libp2p::discv5::Discv5::new(enr, keypair.clone()).unwrap();
    let mut swarm = libp2p::Swarm::new(transport, discv5, keypair.public().into_peer_id());

    // if we know of another peer's ENR, add it known peers
    if let Some(base64_enr) = std::env::args().nth(3) {
        if let Ok(enr) = libp2p::enr::Enr::try_from(base64_enr) {
            swarm.add_enr(enr);
        } else {
            panic!("Decoding ENR failed");
        }
    }

    // construct a 30 second interval to search for new peers.
    let mut query_interval = tokio::timer::Interval::new_interval(Duration::from_secs(30));

    // Kick it off!
    tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
        loop {
            // start a query if it's time to do so
            while let Ok(Async::Ready(_)) = query_interval.poll() {
                // pick a random node target
                let target_random_node_id = libp2p::enr::NodeId::random();
                println!("Connected Peers: {}", swarm.connected_peers());
                println!("Searching for peers...");
                // execute a FINDNODE query
                swarm.find_node(target_random_node_id);
            }

            match swarm.poll().expect("Error while polling swarm") {
                Async::Ready(Some(event)) => match event {
                    Discv5Event::FindNodeResult { closer_peers, .. } => {
                        if !closer_peers.is_empty() {
                            println!("Query Completed. Nodes found:");
                            for n in closer_peers {
                                println!("Node: {}", n);
                            }
                        } else {
                            println!("Query Completed. No peers found.")
                        }
                    }
                    _ => println!("Event: {:?}", event),
                },
                Async::Ready(Some(_)) => (),
                Async::Ready(None) | Async::NotReady => break,
            }
        }

        Ok(Async::NotReady)
    }));
}
