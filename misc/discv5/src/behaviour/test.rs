#![cfg(test)]

use crate::{Discv5, Discv5Event};
use libp2p_core::{
    identity,
    muxing::StreamMuxerBox,
    nodes::Substream,
    transport::{boxed::Boxed, MemoryTransport},
    upgrade, PeerId, Swarm, Transport,
};
use simple_logger;
use tokio::prelude::*;

use enr::NodeId;
use enr::{Enr, EnrBuilder};
use libp2p_secio::SecioConfig;
use libp2p_yamux as yamux;
use std::io;
use std::net::IpAddr;

use tokio::runtime::Runtime;

type SwarmType =
    Swarm<Boxed<(PeerId, StreamMuxerBox), io::Error>, Discv5<Substream<StreamMuxerBox>>>;

fn build_swarms(n: usize) -> Vec<SwarmType> {
    let base_port = 10000u16;
    let mut swarms = Vec::new();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    for port in base_port..base_port + n as u16 {
        let keypair = identity::Keypair::generate_secp256k1();
        let enr = EnrBuilder::new()
            .ip(ip.clone().into())
            .udp(port)
            .build(&keypair)
            .unwrap();
        // unused transport for building a swarm
        let transport = MemoryTransport::default()
            .with_upgrade(SecioConfig::new(keypair.clone()))
            .and_then(move |out, endpoint| {
                let peer_id = out.remote_key.into_peer_id();
                let yamux = yamux::Config::default();
                upgrade::apply(out.stream, yamux, endpoint)
                    .map(|muxer| (peer_id, StreamMuxerBox::new(muxer)))
            })
            .map_err(|e| panic!("Failed to create transport: {:?}", e))
            .boxed();
        let discv5 = Discv5::new(enr, keypair.clone()).unwrap();
        swarms.push(Swarm::new(
            transport,
            discv5,
            keypair.public().into_peer_id(),
        ));
    }
    swarms
}

#[test]
fn test_findnode_query() {
    let _ = simple_logger::init_with_level(log::Level::Debug);
    // build a collection of 10 nodes
    let node_num = 3;
    let mut swarms = build_swarms(node_num);
    let node_enrs: Vec<Enr> = swarms.iter().map(|n| n.local_enr().clone()).collect();

    // link the nodes together
    for (swarm, previous_node_enr) in swarms.iter_mut().skip(1).zip(node_enrs.clone()) {
        swarm.add_enr(previous_node_enr);
    }

    // pick a random node target
    let target_random_node_id = NodeId::random();

    // start a query on the last node
    swarms
        .last_mut()
        .unwrap()
        .find_node(target_random_node_id.clone());

    // build expectations
    let expected_node_ids: Vec<NodeId> = node_enrs
        .iter()
        .map(|enr| enr.node_id().clone())
        .take(node_num - 1)
        .collect();

    Runtime::new()
        .unwrap()
        .block_on(future::poll_fn(move || -> Result<_, io::Error> {
            for (i, swarm) in swarms.iter_mut().enumerate() {
                loop {
                    match swarm.poll().unwrap() {
                        Async::Ready(Some(Discv5Event::FindNodeResult { key, closer_peers })) => {
                            println!("Search key: {}, node_ids:{:?}", key, closer_peers);
                            return Ok(Async::Ready(()));
                        }
                        Async::Ready(Some(Discv5Event::EnrAdded { enr, .. })) => {
                            println!("Enr added, NodeId:{}", enr.node_id());
                        }
                        Async::Ready(Some(event)) => {
                            println!("Event received: {:?}", event);
                        }
                        Async::Ready(_) => {}
                        Async::NotReady => break,
                    }
                }
            }
            Ok(Async::NotReady)
        }))
        .unwrap();
}
