use crate::kbucket;
use crate::packet::NodeId;
use fnv::FnvHashMap;
use libp2p_core::Multiaddr;
use sha2::digest::generic_array::GenericArray;
use smallvec::SmallVec;

const MAX_FINDNODE_REQUESTS: usize = 3;

/// Information about a query.
#[derive(Debug, Clone, PartialEq)]
pub struct QueryInfo {
    /// What we are querying and why.
    pub query_type: QueryType,
    /// Temporary addresses used when trying to reach nodes.
    pub untrusted_addresses: FnvHashMap<NodeId, SmallVec<[Multiaddr; 8]>>,
}

/// Additional information about the query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryType {
    /// The user requested a `FIND_PEER` query to be performed. It should be reported when finished.
    FindNode(NodeId),
}

impl Into<kbucket::Key<QueryInfo>> for QueryInfo {
    fn into(self) -> kbucket::Key<QueryInfo> {
        match self.query_type {
            QueryType::FindNode(node_id) => {
                kbucket::Key::new_raw(self, *GenericArray::from_slice(&node_id))
            }
        }
    }
}

impl QueryInfo {
    pub fn iterations(&self) -> usize {
        match &self.query_type {
            QueryType::FindNode(_) => MAX_FINDNODE_REQUESTS,
        }
    }
}
