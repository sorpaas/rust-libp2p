use enr::Enr;
//use log::debug;
use std::net::IpAddr;

type TopicHash = [u8; 32];

#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolMessage {
    pub id: u64,
    pub body: RpcType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RpcType {
    Request(Request),
    Response(Response),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    Ping { enr_seq: u64 },
    FindNode { distance: u64 },
    Ticket { topic: TopicHash },
    RegisterTopic { ticket: Vec<u8> },
    TopicQuery { topic: TopicHash },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    Ping { enr_seq: u64, ip: IpAddr, port: u16 },
    Nodes { total: u64, nodes: Vec<Enr> },
    Ticket { ticket: Vec<u8>, wait_time: u64 },
    RegisterTopic { registered: bool },
}

impl Response {
    /// Determines if the response is a valid response to the given request.
    pub fn match_request(&self, req: &Request) -> bool {
        match self {
            Response::Ping { .. } => {
                if let Request::Ping { .. } = req {
                    true
                } else {
                    false
                }
            }
            Response::Nodes { .. } => match req {
                Request::FindNode { .. } => true,
                Request::TopicQuery { .. } => true,
                _ => false,
            },
            Response::Ticket { .. } => {
                if let Request::Ticket { .. } = req {
                    true
                } else {
                    false
                }
            }
            Response::RegisterTopic { .. } => {
                if let Request::TopicQuery { .. } = req {
                    true
                } else {
                    false
                }
            }
        }
    }
}

impl std::fmt::Display for RpcType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RpcType::Request(request) => write!(f, "{:?}", request),
            RpcType::Response(response) => write!(f, "{}", response),
        }
    }
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Response::Ping { enr_seq, ip, port } => write!(
                f,
                "PING Response: Enr-seq: {}, Ip: {:?},  Port: {}",
                enr_seq, ip, port
            ),
            Response::Nodes { total, nodes } => {
                let _ = write!(f, "NODES Response: total: {}, Nodes: [", total);
                let mut first = true;
                for id in nodes {
                    if !first {
                        write!(f, ", {}", id)?;
                    } else {
                        write!(f, "{}", id)?;
                    }
                    first = false;
                }

                write!(f, "]")
            }
            Response::Ticket { ticket, wait_time } => write!(
                f,
                "TICKET Response: Ticket: {:?}, Wait time: {}",
                ticket, wait_time
            ),
            Response::RegisterTopic { registered } => {
                write!(f, "REGTOPIC Response: Registered: {}", registered)
            }
        }
    }
}

impl std::fmt::Display for ProtocolMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Message: Id: {}, Body: {}", self.id, self.body)
    }
}

impl ProtocolMessage {
    pub fn msg_type(&self) -> u8 {
        match &self.body {
            RpcType::Request(request) => match request {
                Request::Ping { .. } => 1,
                Request::FindNode { .. } => 3,
                Request::Ticket { .. } => 5,
                Request::RegisterTopic { .. } => 7,
                Request::TopicQuery { .. } => 9,
            },
            RpcType::Response(response) => match response {
                Response::Ping { .. } => 2,
                Response::Nodes { .. } => 4,
                Response::Ticket { .. } => 6,
                Response::RegisterTopic { .. } => 8,
            },
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
        match &self.body {
            RpcType::Request(request) => match request {
                Request::Ping { enr_seq } => {
                    buf.push(msg_type);
                    buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                        self.id(),
                        enr_seq.to_be_bytes().to_vec(),
                    ]));
                    buf
                }
                Request::FindNode { distance } => {
                    buf.push(msg_type);
                    buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                        id,
                        distance.to_be_bytes().to_vec(),
                    ]));
                    buf
                }
                Request::Ticket { topic } => {
                    buf.push(msg_type);
                    buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                        id,
                        topic.to_vec(),
                    ]));
                    buf
                }
                Request::RegisterTopic { ticket } => {
                    buf.push(msg_type);
                    buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                        id,
                        ticket.to_vec(),
                    ]));
                    buf
                }
                Request::TopicQuery { topic } => {
                    buf.push(msg_type);
                    buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                        id,
                        topic.to_vec(),
                    ]));
                    buf
                }
            },
            RpcType::Response(response) => match response {
                Response::Ping { enr_seq, ip, port } => {
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
                Response::Nodes { total, nodes } => {
                    buf.push(msg_type);
                    let enr_list: Vec<Vec<u8>> =
                        nodes.iter().cloned().map(|enr| enr.encode()).collect();
                    let rlp_enr_list = rlp::encode_list::<Vec<u8>, Vec<u8>>(&enr_list);
                    buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                        id,
                        total.to_be_bytes().to_vec(),
                        rlp_enr_list,
                    ]));
                    buf
                }
                Response::Ticket { ticket, wait_time } => {
                    buf.push(msg_type);
                    buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                        id,
                        ticket.to_vec(),
                        wait_time.to_be_bytes().to_vec(),
                    ]));
                    buf
                }
                Response::RegisterTopic { registered } => {
                    buf.push(msg_type);
                    buf.extend_from_slice(&rlp::encode_list::<Vec<u8>, Vec<u8>>(&[
                        id,
                        vec![*registered as u8],
                    ]));
                    buf
                }
            },
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
                RpcType::Request(Request::Ping {
                    enr_seq: u64_from_be_vec(&rlp_list.remove(0))?,
                })
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
                RpcType::Response(Response::Ping {
                    enr_seq: u64_from_be_vec(&rlp_list[0])?,
                    ip,
                    port,
                })
            }
            3 => {
                // FindNodeRequest
                if rlp_list.len() != 1 {
                    return Err(DecodingError::InvalidRLP(
                        "FindNodeRequest - invalid length",
                    ));
                }
                RpcType::Request(Request::FindNode {
                    distance: u64_from_be_vec(&rlp_list.remove(0))?,
                })
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
                        nodes.push(rlp::decode::<Enr>(&enr).map_err(|e| {
                            DecodingError::InvalidEnr(format!("Invalid ENR: {:?}", e))
                        })?);
                    }
                    nodes
                };
                RpcType::Response(Response::Nodes {
                    total: u64_from_be_vec(&rlp_list.remove(0))?,
                    nodes,
                })
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
                RpcType::Request(Request::Ticket { topic })
            }
            6 => {
                // TicketResponse
                if rlp_list.len() != 2 {
                    return Err(DecodingError::InvalidRLP("TicketResponse - invalid length"));
                }
                let ticket = rlp_list.remove(0);
                let wait_time = u64_from_be_vec(&rlp_list.remove(0))?;
                RpcType::Response(Response::Ticket { ticket, wait_time })
            }
            7 => {
                // RegisterTopicRequest
                if rlp_list.len() != 1 {
                    return Err(DecodingError::InvalidRLP(
                        "RegisterTopicRequest - invalid length",
                    ));
                }
                let ticket = rlp_list.remove(0);
                RpcType::Request(Request::RegisterTopic { ticket })
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
                let registered = registered_bytes[0] == 1;
                RpcType::Response(Response::RegisterTopic { registered })
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
                RpcType::Request(Request::TopicQuery { topic })
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
    InvalidEnr(String),
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
            body: RpcType::Request(Request::Ping { enr_seq: 15 }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ping_response() {
        let request = ProtocolMessage {
            id: 10,
            body: RpcType::Response(Response::Ping {
                enr_seq: 15,
                ip: "127.0.0.1".parse().unwrap(),
                port: 80,
            }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_find_node_request() {
        let request = ProtocolMessage {
            id: 10,
            body: RpcType::Request(Request::FindNode { distance: 1337 }),
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
            body: RpcType::Response(Response::Nodes {
                total: 1,
                nodes: enr_list,
            }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ticket_request() {
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Request(Request::Ticket { topic: [17u8; 32] }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ticket_response() {
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Response(Response::Ticket {
                ticket: vec![1, 2, 3, 4, 5],
                wait_time: 5,
            }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_register_topic_request() {
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Request(Request::RegisterTopic {
                ticket: vec![1, 2, 3, 4, 5],
            }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_register_topic_response() {
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Response(Response::RegisterTopic { registered: true }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_topic_query_request() {
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Request(Request::TopicQuery { topic: [17u8; 32] }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }
}
