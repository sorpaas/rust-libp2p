use crate::packet::NodeId;
use fnv::FnvHashMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const PING_VOTE_TIMEOUT: u64 = 300;

pub(crate) struct IpVote {
    votes: HashMap<NodeId, (SocketAddr, Instant)>,
}

impl IpVote {
    pub fn new() -> Self {
        IpVote {
            votes: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: NodeId, socket: SocketAddr) {
        self.votes.insert(
            key,
            (
                socket,
                Instant::now() + Duration::from_secs(PING_VOTE_TIMEOUT),
            ),
        );
    }

    pub fn majority(&mut self) -> Option<SocketAddr> {
        // remove expired
        let instant = Instant::now();
        self.votes.retain(|_, v| v.1 > instant);

        // count votes, take majority
        let mut ip_count: FnvHashMap<SocketAddr, usize> = FnvHashMap::default();
        for (socket, _) in self.votes.values() {
            *ip_count.entry(*socket).or_insert_with(|| 0) += 1;
        }

        ip_count.into_iter().max_by_key(|v| v.1).map(|v| v.0)
    }
}
