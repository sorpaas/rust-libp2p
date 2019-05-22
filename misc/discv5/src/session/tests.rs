#[cfg(test)]
mod tests {

    use super::super::*;
    use libp2p_core::identity::Keypair;
    use simple_logger;
    use tokio::prelude::*;
    use tokio_timer::Delay;

    #[test]
    fn simple_session_message() {
        let _ = simple_logger::init_with_level(log::Level::Debug);

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let socket = SocketAddr::new(ip, 5000);
        let keypair = Keypair::generate_secp256k1();

        let mut service = SessionService::new(socket, keypair.clone(), None).unwrap();

        // send a message after 1 second
        let mut delay = Delay::new(Instant::now() + Duration::from_secs(1));
        let mut delay_expired = false;

        let send_message = Message::decode(vec![0, 1, 2, 3, 4, 5]);
        let target_enr = EnrBuilder::new().ip(ip).tcp(5000).build(&keypair).unwrap();

        let main_stream = stream::poll_fn(move || -> Poll<Option<()>, io::Error> {
            while !delay_expired {
                match delay.poll() {
                    Ok(Async::Ready(_)) => {
                        delay_expired = true;
                        service.send_message(&target_enr, send_message.clone());
                    }
                    Ok(Async::NotReady) | Err(_) => {
                        break;
                    }
                }
            }
            loop {
                let message = match service.poll() {
                    Async::Ready(message) => message,
                    Async::NotReady => return Ok(Async::NotReady),
                };

                match message {
                    SessionMessage::WhoAreYouRequest { src, auth_tag, .. } => {
                        service.send_whoareyou(src, &target_enr, auth_tag);
                    }
                    SessionMessage::Message(message) => {
                        assert_eq!(*message, send_message);
                        return Ok(Async::Ready(None));
                    }
                    _ => {}
                }
            }
        });

        tokio::run(
            main_stream
                .map_err(|err| panic!("{:?}", err))
                .for_each(|_| Ok(())),
        );
    }

    #[test]
    fn multiple_messages() {
        let _ = simple_logger::init_with_level(log::Level::Debug);

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let socket = SocketAddr::new(ip, 5000);
        let keypair = Keypair::generate_secp256k1();

        let mut service = SessionService::new(socket, keypair.clone(), None).unwrap();

        // send a messages after 1 second
        let mut delay = Delay::new(Instant::now() + Duration::from_secs(1));
        let mut delay_expired = false;

        let send_message = Message::decode(vec![0, 1, 2, 3, 4, 5]);
        let mut message_count = 0;
        let messages_to_send = 5;

        let target_enr = EnrBuilder::new().ip(ip).tcp(5000).build(&keypair).unwrap();

        let main_stream = stream::poll_fn(move || -> Poll<Option<()>, io::Error> {
            while !delay_expired {
                match delay.poll() {
                    Ok(Async::Ready(_)) => {
                        delay_expired = true;
                        for _ in 0..messages_to_send {
                            service.send_message(&target_enr, send_message.clone());
                        }
                    }
                    Ok(Async::NotReady) | Err(_) => {
                        break;
                    }
                }
            }
            loop {
                let message = match service.poll() {
                    Async::Ready(message) => message,
                    Async::NotReady => return Ok(Async::NotReady),
                };

                match message {
                    SessionMessage::WhoAreYouRequest { src, auth_tag, .. } => {
                        service.send_whoareyou(src, &target_enr, auth_tag);
                    }
                    SessionMessage::Message(message) => {
                        assert_eq!(*message, send_message);
                        message_count += 1;
                        if message_count == messages_to_send {
                            return Ok(Async::Ready(None));
                        }
                    }
                    _ => {}
                }
            }
        });

        tokio::run(
            main_stream
                .map_err(|err| panic!("{:?}", err))
                .for_each(|_| Ok(())),
        );
    }
}
