use crate::kbucket::Key;
use crate::packet::NodeId;
use crate::query::ReturnPeer;
use crate::rpc::Request;
use enr::Enr;
use sha2::digest::generic_array::GenericArray;
use smallvec::SmallVec;

const MAX_FINDNODE_REQUESTS: usize = 3;

/// Information about a query.
#[derive(Debug, Clone, PartialEq)]
pub struct QueryInfo {
    /// What we are querying and why.
    pub query_type: QueryType,

    /// Temporary ENRs used when trying to reach nodes.
    pub untrusted_enrs: SmallVec<[Enr; 16]>,
}

/// Additional information about the query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryType {
    /// The user requested a `FIND_PEER` query to be performed. It should be reported when finished.
    FindNode(NodeId),
}

impl QueryInfo {
    /// Builds an RPC Request
    pub fn into_rpc_request(
        &self,
        return_peer: &ReturnPeer<NodeId>,
    ) -> Result<Request, &'static str> {
        let request = match &self.query_type {
            QueryType::FindNode(node_id) => {
                let distance = findnode_log2distance(node_id, return_peer)
                    .ok_or_else(|| "Requested a node find itself")?;
                Request::FindNode { distance }
            }
        };

        Ok(request)
    }

    pub fn iterations(&self) -> usize {
        match &self.query_type {
            QueryType::FindNode(_) => MAX_FINDNODE_REQUESTS,
        }
    }
}

impl Into<Key<QueryInfo>> for QueryInfo {
    fn into(self) -> Key<QueryInfo> {
        match self.query_type {
            QueryType::FindNode(node_id) => Key::new_raw(self, *GenericArray::from_slice(&node_id)),
        }
    }
}

/// Calculates the log2 distance for a destination peer given a target and current iteration.
///
/// As the iteration increases, FINDNODE requests adjacent distances from the exact peer distance.
///
/// As an example, if the target has a distance of 12 from the remote peer, the sequence of distances that are sent for increasing iterations would be [12, 11, 13, 10, 14, .. ].
fn findnode_log2distance(target: &NodeId, return_peer: &ReturnPeer<NodeId>) -> Option<u64> {
    let iteration = return_peer.iteration as u64;
    if iteration > 127 {
        // invoke and endless loop - coding error
        panic!("Iterations cannot be greater than 127");
    }

    let dst_key: Key<NodeId> = return_peer.node_id.clone().into();

    let distance = dst_key.log2_distance(&target.clone().into())?;

    let mut result_list = vec![distance];
    let mut difference = 1;
    while (result_list.len() as u64) < iteration {
        if let Some(d) = distance.checked_sub(difference) {
            result_list.push(d);
        }
        if (result_list.len() as u64) < iteration && distance + difference <= 256 {
            result_list.push(distance + difference);
        }
        difference += 1;
    }
    Some(result_list.pop().expect("List must have values"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2distance() {
        let target: NodeId = [0u8; 32];
        let mut destination: NodeId = [0u8; 32];
        destination[10] = 1; // gives a log2 distance of 168
        let dst_key: Key<NodeId> = destination.into();
        let log2_distance = dst_key.log2_distance(&target.into());

        let expected_distances = vec![168, 167, 169, 166, 170, 165, 171, 164, 172];

        for (iteration, value) in expected_distances.iter().enumerate() {
            let return_peer = ReturnPeer {
                node_id: destination.clone(),
                iteration: iteration + 1,
            };
            assert_eq!(
                findnode_log2distance(&target, &return_peer).unwrap(),
                expected_distances[iteration]
            );
        }
    }

    #[test]
    fn test_log2distance_lower() {
        let target: NodeId = [0u8; 32];
        let mut destination: NodeId = [0u8; 32];
        destination[31] = 16; // gives a log2 distance of 4
        let dst_key: Key<NodeId> = destination.into();
        let log2_distance = dst_key.log2_distance(&target.into());

        let expected_distances = vec![4, 3, 5, 2, 6, 1, 7, 0, 8, 9, 10];

        for (iteration, value) in expected_distances.iter().enumerate() {
            let return_peer = ReturnPeer {
                node_id: destination.clone(),
                iteration: iteration + 1,
            };
            assert_eq!(
                findnode_log2distance(&target, &return_peer).unwrap(),
                expected_distances[iteration]
            );
        }
    }

    #[test]
    fn test_log2distance_upper() {
        let target: NodeId = [0u8; 32];
        let mut destination: NodeId = [0u8; 32];
        destination[0] = 16; // gives a log2 distance of 252
        let dst_key: Key<NodeId> = destination.into();
        let log2_distance = dst_key.log2_distance(&target.into());

        let expected_distances = vec![252, 251, 253, 250, 254, 249, 255, 248, 256, 247, 246];

        for (iteration, value) in expected_distances.iter().enumerate() {
            let return_peer = ReturnPeer {
                node_id: destination.clone(),
                iteration: iteration + 1,
            };
            assert_eq!(
                findnode_log2distance(&target, &return_peer).unwrap(),
                expected_distances[iteration]
            );
        }
    }
}
