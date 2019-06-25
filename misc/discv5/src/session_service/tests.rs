#![cfg(test)]
use super::*;
use crate::rpc::{Request, RpcType};
use enr::EnrBuilder;
use libp2p_core::identity::Keypair;
use std::net::IpAddr;
use tokio::prelude::*;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn simple_session_message() {
    init();

    let sender_port = 5000;
    let receiver_port = 5001;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let keypair = Keypair::generate_secp256k1();
    let keypair_2 = Keypair::generate_secp256k1();

    let sender_enr = EnrBuilder::new()
        .ip(ip)
        .udp(sender_port)
        .build(&keypair)
        .unwrap();
    let receiver_enr = EnrBuilder::new()
        .ip(ip)
        .udp(receiver_port)
        .build(&keypair_2)
        .unwrap();

    let mut sender_service =
        SessionService::new(sender_enr.clone(), keypair.clone(), ip.into()).unwrap();
    let mut receiver_service =
        SessionService::new(receiver_enr.clone(), keypair_2.clone(), ip.into()).unwrap();

    let send_message = ProtocolMessage {
        id: 1,
        body: RpcType::Request(Request::Ping { enr_seq: 1 }),
    };

    let receiver_send_message = send_message.clone();

    let _ = sender_service.send_request(&receiver_enr, send_message);

    let sender = future::poll_fn(move || -> Poll<(), ()> {
        loop {
            match sender_service.poll() {
                Async::Ready(_) => {}
                Async::NotReady => return Ok(Async::NotReady),
            };
        }
    });

    let receiver = future::poll_fn(move || -> Poll<(), ()> {
        loop {
            let message = match receiver_service.poll() {
                Async::Ready(message) => message,
                Async::NotReady => return Ok(Async::NotReady),
            };

            match message {
                SessionEvent::WhoAreYouRequest { src, auth_tag, .. } => {
                    let seq = sender_enr.seq;
                    let node_id = sender_enr.node_id();
                    receiver_service.send_whoareyou(
                        src,
                        node_id,
                        seq,
                        Some(sender_enr.clone()),
                        auth_tag,
                    );
                }
                SessionEvent::Message { message, .. } => {
                    assert_eq!(*message, receiver_send_message);
                    return Ok(Async::Ready(()));
                }
                _ => {}
            }
        }
    });

    tokio::run(
        sender
            .select(receiver)
            .map_err(|_| panic!("failed"))
            .map(|_| ()),
    );
}

#[test]
fn multiple_messages() {
    init();
    let sender_port = 5002;
    let receiver_port = 5003;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let keypair = Keypair::generate_secp256k1();
    let keypair_2 = Keypair::generate_secp256k1();

    let sender_enr = EnrBuilder::new()
        .ip(ip)
        .udp(sender_port)
        .build(&keypair)
        .unwrap();
    let receiver_enr = EnrBuilder::new()
        .ip(ip)
        .udp(receiver_port)
        .build(&keypair_2)
        .unwrap();

    let mut sender_service =
        SessionService::new(sender_enr.clone(), keypair.clone(), ip.into()).unwrap();
    let mut receiver_service =
        SessionService::new(receiver_enr.clone(), keypair_2.clone(), ip.into()).unwrap();

    let send_message = ProtocolMessage {
        id: 1,
        body: RpcType::Request(Request::Ping { enr_seq: 1 }),
    };

    let receiver_send_message = send_message.clone();

    let messages_to_send = 5;

    for _ in 0..messages_to_send {
        let _ = sender_service.send_request(&receiver_enr, send_message.clone());
    }

    let mut message_count = 0;

    let sender = future::poll_fn(move || -> Poll<(), ()> {
        loop {
            match sender_service.poll() {
                Async::Ready(_) => {}
                Async::NotReady => return Ok(Async::NotReady),
            };
        }
    });

    let receiver = future::poll_fn(move || -> Poll<(), ()> {
        loop {
            let message = match receiver_service.poll() {
                Async::Ready(message) => message,
                Async::NotReady => return Ok(Async::NotReady),
            };

            match message {
                SessionEvent::WhoAreYouRequest { src, auth_tag, .. } => {
                    let seq = sender_enr.seq;
                    let node_id = &sender_enr.node_id();
                    receiver_service.send_whoareyou(
                        src,
                        node_id,
                        seq,
                        Some(sender_enr.clone()),
                        auth_tag,
                    );
                }
                SessionEvent::Message { message, .. } => {
                    assert_eq!(*message, receiver_send_message);
                    message_count += 1;
                    if message_count == messages_to_send {
                        return Ok(Async::Ready(()));
                    }
                }
                _ => {}
            }
        }
    });

    tokio::run(
        sender
            .select(receiver)
            .map_err(|_| panic!("failed"))
            .map(|_| ()),
    );
}
