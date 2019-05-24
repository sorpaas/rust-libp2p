use enr::Enr;
//use log::debug;
use std::net::IpAddr;

type TopicHash = [u8; 32];

#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolMessage {
    pub id: u64,
    pub body: MessageType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MessageType {
    PingRequest { enr_seq: u64 },
    PingResponse { enr_seq: u64, ip: IpAddr, port: u16 },
    FindNodeRequest { distance: u64 },
    NodesResponse { total: u64, nodes: Vec<Enr> },
    TicketRequest { topic: TopicHash },
    TicketResponse { ticket: Vec<u8>, wait_time: u64 },
    RegisterTopicRequest { ticket: Vec<u8> },
    RegisterTopicResponse { registered: bool },
    TopicQueryRequest { topic: TopicHash },
}

impl ProtocolMessage {
    pub fn msg_type(&self) -> u8 {
        match &self.body {
            MessageType::PingRequest { .. } => 1,
            MessageType::PingResponse { .. } => 2,
            MessageType::FindNodeRequest { .. } => 3,
            MessageType::NodesResponse { .. } => 4,
            MessageType::TicketRequest { .. } => 5,
            MessageType::TicketResponse { .. } => 6,
            MessageType::RegisterTopicRequest { .. } => 7,
            MessageType::RegisterTopicResponse { .. } => 8,
            MessageType::TopicQueryRequest { .. } => 9,
        }
    }

    pub fn is_response(&self) -> bool {
        match self.body {
            MessageType::PingRequest { .. } => false,
            MessageType::PingResponse { .. } => true,
            MessageType::FindNodeRequest { .. } => false,
            MessageType::NodesResponse { .. } => true,
            MessageType::TicketRequest { .. } => false,
            MessageType::TicketResponse { .. } => true,
            MessageType::RegisterTopicRequest { .. } => false,
            MessageType::RegisterTopicResponse { .. } => true,
            MessageType::TopicQueryRequest { .. } => false,
        }
    }

    fn id(&self) -> Vec<u8> {
        self.id.to_be_bytes().to_vec()
    }

    /// Encodes a ProtocolMessage to RLP-encoded bytes.
    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10);
        let msg_type = self.msg_type();
        let id = self.id();
        match self.body {
            MessageType::PingRequest { enr_seq } => {
                buf.push(msg_type);
                buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                    self.id(),
                    enr_seq.to_be_bytes().to_vec(),
                ]));
                buf
            }
            MessageType::PingResponse { enr_seq, ip, port } => {
                buf.push(msg_type);
                let ip_bytes = match ip {
                    IpAddr::V4(addr) => addr.octets().to_vec(),
                    IpAddr::V6(addr) => addr.octets().to_vec(),
                };
                buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                    id,
                    enr_seq.to_be_bytes().to_vec(),
                    ip_bytes,
                    port.to_be_bytes().to_vec(),
                ]));
                buf
            }
            MessageType::FindNodeRequest { distance } => {
                buf.push(msg_type);
                buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                    id,
                    distance.to_be_bytes().to_vec(),
                ]));
                buf
            }
            MessageType::NodesResponse { total, nodes } => {
                buf.push(msg_type);
                let enr_list: Vec<Vec<u8>> = nodes.into_iter().map(|enr| enr.encode()).collect();
                let rlp_enr_list = rlp::encode_list::<Vec<u8>, Vec<u8>>(&enr_list);
                buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                    id,
                    total.to_be_bytes().to_vec(),
                    rlp_enr_list,
                ]));
                buf
            }
            MessageType::TicketRequest { topic } => {
                buf.push(msg_type);
                buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[id, topic.to_vec()]));
                buf
            }
            MessageType::TicketResponse { ticket, wait_time } => {
                buf.push(msg_type);
                buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                    id,
                    ticket.to_vec(),
                    wait_time.to_be_bytes().to_vec(),
                ]));
                buf
            }
            MessageType::RegisterTopicRequest { ticket } => {
                buf.push(msg_type);
                buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                    id,
                    ticket.to_vec(),
                ]));
                buf
            }
            MessageType::RegisterTopicResponse { registered } => {
                buf.push(msg_type);
                buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                    id,
                    vec![registered as u8],
                ]));
                buf
            }
            MessageType::TopicQueryRequest { topic } => {
                buf.push(msg_type);
                buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[id, topic.to_vec()]));
                buf
            }
        }
    }

    pub fn decode(data: Vec<u8>) -> Result<Self, DecodingError> {
        if data.len() < 9 {
            return Err(DecodingError::TooSmall);
        }

        let msg_type = data[0];

        let rlp = rlp::Rlp::new(&data[1..]);
        let mut rlp_list = rlp
            .as_list::<Vec<u8>>()
            .map_err(|_| DecodingError::InvalidRLP("not a list"))?;

        if rlp_list.len() < 2 {
            return Err(DecodingError::InvalidRLP("list to short"));
        }

        let id = u64_from_be_vec(&rlp_list.remove(0))?;

        let body = match msg_type {
            1 => {
                // PingRequest
                if rlp_list.len() != 1 {
                    return Err(DecodingError::InvalidRLP("ping request - invalid length"));
                }
                MessageType::PingRequest {
                    enr_seq: u64_from_be_vec(&rlp_list.remove(0))?,
                }
            }
            2 => {
                // PingResponse
                if rlp_list.len() != 3 {
                    return Err(DecodingError::InvalidRLP("PingResponse - invalid length"));
                }
                let ip_bytes = &rlp_list[1];
                let ip = match ip_bytes.len() {
                    4 => {
                        let mut ip = [0u8; 4];
                        ip.copy_from_slice(ip_bytes);
                        IpAddr::from(ip)
                    }
                    16 => {
                        let mut ip = [0u8; 16];
                        ip.copy_from_slice(ip_bytes);
                        IpAddr::from(ip)
                    }
                    _ => return Err(DecodingError::InvalidRLP("PingResponse - invalid ip")),
                };
                let port = {
                    if rlp_list[2].len() > 2 {
                        return Err(DecodingError::InvalidRLP("Invalid port size"));
                    }
                    let mut port = [0u8; 2];
                    port[2 - rlp_list[2].len()..].copy_from_slice(&rlp_list[2]);
                    u16::from_be_bytes(port)
                };
                MessageType::PingResponse {
                    enr_seq: u64_from_be_vec(&rlp_list[0])?,
                    ip,
                    port,
                }
            }
            3 => {
                // FindNodeRequest
                if rlp_list.len() != 1 {
                    return Err(DecodingError::InvalidRLP(
                        "FindNodeRequest - invalid length",
                    ));
                }
                MessageType::FindNodeRequest {
                    distance: u64_from_be_vec(&rlp_list.remove(0))?,
                }
            }
            4 => {
                // NodesResponse
                if rlp_list.len() != 2 {
                    return Err(DecodingError::InvalidRLP("NodesResponse - invalid length"));
                }
                let nodes = {
                    let enr = rlp_list.pop().expect("value exists");
                    let rlp_enr_list = rlp::Rlp::new(&enr);
                    let enr_list = rlp_enr_list.as_list::<Vec<u8>>().map_err(|_| {
                        DecodingError::InvalidRLP("NodesResponse - Invalid ENR list")
                    })?;
                    let mut nodes = vec![];
                    for enr in enr_list.into_iter() {
                        nodes.push(
                            rlp::decode::<Enr>(&enr)
                                .map_err(|_| DecodingError::InvalidRLP("Invalid ENR Encoding"))?,
                        );
                    }
                    nodes
                };
                MessageType::NodesResponse {
                    total: u64_from_be_vec(&rlp_list.remove(0))?,
                    nodes,
                }
            }
            5 => {
                // TicketRequest
                if rlp_list.len() != 1 {
                    return Err(DecodingError::InvalidRLP("TicketRequest - invalid length"));
                }
                let topic = {
                    let topic_bytes = rlp_list.remove(0);
                    if topic_bytes.len() != 32 {
                        return Err(DecodingError::InvalidRLP(
                            "TicketRequest - invalid hash length",
                        ));
                    }
                    let mut topic = [0u8; 32];
                    topic.copy_from_slice(&topic_bytes);
                    topic
                };
                MessageType::TicketRequest { topic }
            }
            6 => {
                // TicketResponse
                if rlp_list.len() != 2 {
                    return Err(DecodingError::InvalidRLP("TicketResponse - invalid length"));
                }
                let ticket = rlp_list.remove(0);
                let wait_time = u64_from_be_vec(&rlp_list.remove(0))?;
                MessageType::TicketResponse { ticket, wait_time }
            }
            7 => {
                // RegisterTopicRequest
                if rlp_list.len() != 1 {
                    return Err(DecodingError::InvalidRLP(
                        "RegisterTopicRequest - invalid length",
                    ));
                }
                let ticket = rlp_list.remove(0);
                MessageType::RegisterTopicRequest { ticket }
            }
            8 => {
                // RegisterTopicResponse
                if rlp_list.len() != 1 {
                    return Err(DecodingError::InvalidRLP(
                        "RegisterTopicResponse - invalid length",
                    ));
                }
                let registered_bytes = rlp_list.remove(0);
                if registered_bytes.len() != 1 {
                    return Err(DecodingError::InvalidValue);
                }
                let mut registered = false;
                if registered_bytes[0] == 1 {
                    registered = true;
                }
                MessageType::RegisterTopicResponse { registered }
            }
            9 => {
                // TopicQueryRequest
                if rlp_list.len() != 1 {
                    return Err(DecodingError::InvalidRLP(
                        "TopicQueryRequest - invalid length",
                    ));
                }
                let topic = {
                    let topic_bytes = rlp_list.remove(0);
                    if topic_bytes.len() != 32 {
                        return Err(DecodingError::InvalidRLP(
                            "TopicQueryRequest - invalid hash length",
                        ));
                    }
                    let mut topic = [0u8; 32];
                    topic.copy_from_slice(&topic_bytes);
                    topic
                };
                MessageType::TopicQueryRequest { topic }
            }
            _ => {
                return Err(DecodingError::UnknownMessageType);
            }
        };

        Ok(ProtocolMessage { id, body })
    }
}

#[derive(Debug)]
pub enum DecodingError {
    InvalidU64Size,
    TooSmall,
    InvalidRLP(&'static str),
    UnknownMessageType,
    InvalidValue,
}

#[inline]
fn u64_from_be_vec(data: &[u8]) -> Result<u64, DecodingError> {
    if data.len() > 8 {
        return Err(DecodingError::InvalidU64Size);
    }
    let mut val = [0u8; 8];
    val[8 - data.len()..].copy_from_slice(data);
    Ok(u64::from_be_bytes(val))
}

#[derive(Debug, Clone)]
pub enum PacketError {
    UnknownFormat,
    UnknownPacket,
    TooSmall,
}

#[cfg(test)]
mod tests {
    use super::*;
    use enr::EnrBuilder;
    use libp2p_core::identity::Keypair;

    #[test]
    fn encode_decode_ping_request() {
        let request = ProtocolMessage {
            id: 10,
            body: MessageType::PingRequest { enr_seq: 15 },
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ping_response() {
        let request = ProtocolMessage {
            id: 10,
            body: MessageType::PingResponse {
                enr_seq: 15,
                ip: "127.0.0.1".parse().unwrap(),
                port: 80,
            },
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_find_node_request() {
        let request = ProtocolMessage {
            id: 10,
            body: MessageType::FindNodeRequest { distance: 1337 },
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_nodes_response() {
        let kp = Keypair::generate_ed25519();
        let enr1 = EnrBuilder::new()
            .ip("127.0.0.1".parse().unwrap())
            .udp(500)
            .build(&kp)
            .unwrap();
        let enr2 = EnrBuilder::new()
            .ip("10.0.0.1".parse().unwrap())
            .tcp(8080)
            .build(&kp)
            .unwrap();
        let enr3 = EnrBuilder::new()
            .ip("10.4.5.6".parse().unwrap())
            .build(&kp)
            .unwrap();

        let enr_list = vec![enr1, enr2, enr3];
        let request = ProtocolMessage {
            id: 0,
            body: MessageType::NodesResponse {
                total: 1,
                nodes: enr_list,
            },
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ticket_request() {
        let request = ProtocolMessage {
            id: 0,
            body: MessageType::TicketRequest { topic: [17u8; 32] },
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ticket_response() {
        let request = ProtocolMessage {
            id: 0,
            body: MessageType::TicketResponse {
                ticket: vec![1, 2, 3, 4, 5],
                wait_time: 5,
            },
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_register_topic_request() {
        let request = ProtocolMessage {
            id: 0,
            body: MessageType::RegisterTopicRequest {
                ticket: vec![1, 2, 3, 4, 5],
            },
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_register_topic_response() {
        let request = ProtocolMessage {
            id: 0,
            body: MessageType::RegisterTopicResponse { registered: true },
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_topic_query_request() {
        let request = ProtocolMessage {
            id: 0,
            body: MessageType::TopicQueryRequest { topic: [17u8; 32] },
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }
}
