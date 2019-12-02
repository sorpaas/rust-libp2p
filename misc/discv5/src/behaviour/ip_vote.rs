use enr::NodeId;
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

    /// Returns the majority `SocketAddr`. This is simply the `SocketAddr` supplied if it is still
    /// the majority, otherwise returns a new `SocketAddr` which has the most votes. If the
    /// supplied `SocketAddr` has the same number of votes as another `SocketAddr`, the supplied
    /// `SocketAddr` is returned.
    pub fn majority(&mut self, current_socket_addr: SocketAddr) -> SocketAddr {
        // remove expired
        let instant = Instant::now();
        self.votes.retain(|_, v| v.1 > instant);

        // count votes, take majority
        let mut ip_count: FnvHashMap<SocketAddr, usize> = FnvHashMap::default();
        for (socket, _) in self.votes.values() {
            *ip_count.entry(*socket).or_insert_with(|| 0) += 1;
        }

        let current_majority = ip_count
            .get(&current_socket_addr)
            .cloned()
            .unwrap_or_else(|| 0);

        // find the maximum socket addr
        ip_count
            .into_iter()
            .filter(|v| v.1 > current_majority)
            .max_by_key(|v| v.1)
            .map(|v| v.0)
            .unwrap_or_else(|| current_socket_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::{IpVote, NodeId, SocketAddr};

    #[test]
    fn test_three_way_vote_draw() {
        let mut votes = IpVote::new();
        let socket_1 = SocketAddr::new("127.0.0.1".parse().unwrap(), 1);
        let node_1 = NodeId::random();
        let socket_2 = SocketAddr::new("127.0.0.1".parse().unwrap(), 2);
        let node_2 = NodeId::random();
        let socket_3 = SocketAddr::new("127.0.0.1".parse().unwrap(), 3);
        let node_3 = NodeId::random();

        votes.insert(node_1, socket_1);
        votes.insert(node_2, socket_2);
        votes.insert(node_3, socket_3);

        assert_eq!(votes.majority(socket_1), socket_1);
        assert_eq!(votes.majority(socket_2), socket_2);
        assert_eq!(votes.majority(socket_3), socket_3);
    }

    #[test]
    fn test_majority_vote() {
        let mut votes = IpVote::new();
        let socket_1 = SocketAddr::new("127.0.0.1".parse().unwrap(), 1);
        let node_1 = NodeId::random();
        let socket_2 = SocketAddr::new("127.0.0.1".parse().unwrap(), 2);
        let node_2 = NodeId::random();
        let socket_3 = SocketAddr::new("127.0.0.1".parse().unwrap(), 2);
        let node_3 = NodeId::random();

        votes.insert(node_1, socket_1);
        votes.insert(node_2, socket_2);
        votes.insert(node_3, socket_3);

        assert_eq!(votes.majority(socket_1), socket_2);
        assert_eq!(votes.majority(socket_2), socket_2);
        assert_eq!(votes.majority(socket_3), socket_2);
    }
}
