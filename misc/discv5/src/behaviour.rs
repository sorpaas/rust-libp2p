use self::query_info::{QueryInfo, QueryType};
use crate::kbucket::{self, KBucketsTable, NodeStatus};
use crate::packet::NodeId;
use crate::query::{Query, QueryConfig};
use crate::rpc;
use crate::session_service::SessionService;
use enr::Enr;
use fnv::{FnvHashMap, FnvHashSet};
use futures::prelude::*;
//use futures::{prelude::*, stream};
use libp2p_core::identity::Keypair;
use libp2p_core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p_core::{
    protocols_handler::{DummyProtocolsHandler, ProtocolsHandler},
    Multiaddr, PeerId,
};
use smallvec::SmallVec;
use std::io;
use std::{marker::PhantomData, time::Duration};
use tokio_io::{AsyncRead, AsyncWrite};

mod query_info;

type QueryId = usize;
type RpcId = u64;

#[derive(Clone, PartialEq, Eq, Hash)]
struct RpcRequest(RpcId, NodeId);

pub struct Discv5<TSubstream> {
    /// The local ENR for this node.
    local_enr: Enr,

    /// The keypair for the current node. Required to sign our local ENR when our address is
    /// updated.
    keypair: Keypair,

    events: SmallVec<[Discv5Event; 32]>,
    /// Storage of the ENR record for each node.
    kbuckets: KBucketsTable<NodeId, Enr>,

    /// All the iterative queries we are currently performing, with their ID. The last parameter
    /// is the list of accumulated providers for `GET_PROVIDERS` queries.
    active_queries: FnvHashMap<QueryId, Query<QueryInfo, NodeId>>,

    active_rpc_requests: FnvHashMap<RpcRequest, QueryId>,

    /// List of peers we have established sessions with.
    connected_peers: FnvHashSet<NodeId>,

    /// The configuration for iterative queries.
    query_config: QueryConfig,

    /// Identifier for the next query that we start.
    next_query_id: QueryId,

    /// Main discv5 UDP service that establishes sessions with peers.
    service: SessionService,

    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
}

impl<TSubstream> Discv5<TSubstream> {
    /// Builds the `Discv5` main struct.
    ///
    /// `local_enr` is the `ENR` representing the local node. This contains node identifying information, such
    /// as IP addresses and ports which we wish to broadcast to other nodes via this discovery
    /// mechanism. The `ip` and `port` fields of the ENR will determine the ip/port that the discv5
    /// `Service` will listen on.
    pub fn new(local_enr: Enr, keypair: Keypair) -> io::Result<Self> {
        let service = SessionService::new(local_enr.clone(), keypair.clone())?;
        let query_config = QueryConfig::default();

        Ok(Discv5 {
            local_enr: local_enr.clone(),
            keypair,
            events: SmallVec::new(),
            kbuckets: KBucketsTable::new(local_enr.node_id.into(), Duration::from_secs(60)),
            active_queries: Default::default(),
            active_rpc_requests: Default::default(),
            connected_peers: Default::default(),
            next_query_id: 0,
            query_config,
            service,
            marker: PhantomData,
        })
    }

    /// Adds a known ENR of a peer participating in Discv5 to the
    /// routing table.
    ///
    /// This allows pre-populating the Kademlia routing table with known
    /// addresses, so that they can be used immediately in following DHT
    /// operations involving one of these peers, without having to dial
    /// them upfront.
    pub fn add_enr(&mut self, enr: Enr) {
        let key = kbucket::Key::from(enr.clone().node_id);
        match self.kbuckets.entry(&key) {
            kbucket::Entry::Present(mut entry, _) => {
                *entry.value() = enr;
            }
            kbucket::Entry::Pending(mut entry, _) => {
                *entry.value() = enr;
            }
            kbucket::Entry::Absent(entry) => {
                match entry.insert(enr.clone(), NodeStatus::Disconnected) {
                    kbucket::InsertResult::Inserted => {
                        let event = Discv5Event::EnrAdded {
                            enr,
                            replaced: None,
                        };
                        self.events.push(event);
                    }
                    kbucket::InsertResult::Full => (),
                    kbucket::InsertResult::Pending { disconnected } => {
                        // TODO: Establish connection.  Look up known addresses. Call PING
                    }
                }
                return;
            }
            kbucket::Entry::SelfEntry => return,
        };
    }

    /// Returns an iterator over all ENR node IDs of nodes currently contained in a bucket
    /// of the Kademlia routing table.
    pub fn kbuckets_entries(&mut self) -> impl Iterator<Item = &NodeId> {
        self.kbuckets.iter().map(|entry| entry.node.key.preimage())
    }

    /// Starts an iterative `FIND_NODE` request.
    ///
    /// This will eventually produce an event containing the nodes of the DHT closest to the
    /// requested `PeerId`.
    pub fn find_node(&mut self, node_id: NodeId) {
        self.start_query(QueryType::FindNode(node_id));
    }

    fn send_rpc(&mut self, dst_enr: &Enr, query_info: QueryInfo, query_id: QueryId) {
        let dst_id = dst_enr.node_id;
        // Generate a random rpc_id which is matched per node id
        let id: u64 = rand::random();

        // build a ProtocolMessage from a QueryInfo
        let body = match &query_info.query_type {
            QueryType::FindNode(node_id) => {
                let distance = match self
                    .kbuckets
                    .local_key()
                    .log2_distance(&dst_id.clone().into())
                {
                    Some(v) => v,
                    None => {
                        //dst node is local_key
                        //TODO: Inject on_failure
                        return;
                    }
                };

                rpc::Request::FindNode { distance }
            }
            _ => {
                panic!("Not implemented");
            }
        };

        let req = RpcRequest(id.clone(), dst_id);
        let body = rpc::RpcType::Request(body);

        self.active_rpc_requests.insert(req.clone(), query_id);
        match self
            .service
            .send_message(dst_enr, rpc::ProtocolMessage { id, body })
        {
            Ok(_) => {}
            Err(_) => {
                self.active_rpc_requests.remove(&req);
                // TODO: inject on_failure
            }
        }
    }

    /// Internal function that starts a query.
    fn start_query(&mut self, query_type: QueryType) {
        let query_id = self.next_query_id;
        self.next_query_id += 1;

        let target = QueryInfo {
            query_type: query_type,
            untrusted_addresses: Default::default(),
        };

        // How many times to call the rpc per node.
        // FINDNODE requires multiple iterations
        let query_iterations = target.iterations();

        let target_key: kbucket::Key<QueryInfo> = target.clone().into();

        let known_closest_peers = self.kbuckets.closest_keys(&target_key);
        let query = Query::with_config(
            self.query_config.clone(),
            target,
            known_closest_peers,
            query_iterations,
        );

        self.active_queries.insert(query_id, query);
    }

    /// Processes discovered peers from a query.
    fn discovered<'a, I>(&mut self, query_id: &QueryId, source: &NodeId, peers: I)
    where
        I: Iterator<Item = &'a DiscoveredPeer> + Clone,
    {
        let local_id = self.kbuckets.local_key().preimage().clone();
        let others_iter = peers.filter(|p| p.enr.node_id != local_id);

        for peer in others_iter.clone() {
            self.events.push(Discv5Event::Discovered {
                enr_id: peer.enr.node_id.clone(),
                addresses: peer.enr.multiaddr().clone(),
                ty: peer.connection_type.clone(),
            });
        }

        if let Some(query) = self.active_queries.get_mut(query_id) {
            for peer in others_iter.clone() {
                query.target_mut().untrusted_addresses.insert(
                    peer.enr.node_id.clone(),
                    peer.enr.multiaddr().iter().cloned().collect(),
                );
            }
            query.on_success(source, others_iter.cloned().map(|kp| kp.enr.node_id))
        }
    }

    /// Returns nodes in a specific k-bucket defined by the distance parameter. This is run in the
    /// context of a `source` peer which is not included in the result.
    fn get_nodes_by_distance<T: Clone>(
        &mut self,
        target: &kbucket::Key<T>,
        distance: u64,
        source: &NodeId,
    ) -> Vec<DiscoveredPeer> {
        let local_key = self.kbuckets.local_key().clone();

        self.kbuckets
            .closest(target)
            .filter(|e| e.node.key.preimage() != source)
            .take_while(|e| local_key.log2_distance(&e.node.key) == Some(distance))
            .map(DiscoveredPeer::from)
            .collect()
    }

    /// Update the connection status of a peer in the Kademlia routing table.
    fn connection_updated(&mut self, node_id: NodeId, enr: Option<Enr>, new_status: NodeStatus) {
        let key = kbucket::Key::new(node_id.clone());
        match self.kbuckets.entry(&key) {
            kbucket::Entry::Present(mut entry, old_status) => {
                if let Some(enr) = enr {
                    *entry.value() = enr;
                }
                if old_status != new_status {
                    entry.update(new_status);
                }
            }

            kbucket::Entry::Pending(mut entry, old_status) => {
                if let Some(enr) = enr {
                    *entry.value() = enr;
                }
                if old_status != new_status {
                    entry.update(new_status);
                }
            }

            kbucket::Entry::Absent(entry) => {
                if new_status == NodeStatus::Connected {
                    // Note: If an ENR is not provided, no record is added
                    debug_assert!(enr.is_some());
                    if let Some(enr) = enr {
                        match entry.insert(enr, new_status) {
                            kbucket::InsertResult::Inserted => {
                                let event = Discv5Event::NodeInserted {
                                    node_id: node_id.clone(),
                                    replaced: None,
                                };
                                self.events.push(event);
                            }
                            kbucket::InsertResult::Full => (),
                            kbucket::InsertResult::Pending { disconnected } => {
                                debug_assert!(!self
                                    .connected_peers
                                    .contains(disconnected.preimage()));

                                // TODO: Connect to peer, disconnected.into_preimage().
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Wrapper around a discovered peer that associates a connection type to peer's ENR.
#[derive(Debug, Clone)]
struct DiscoveredPeer {
    enr: Enr,
    connection_type: ConnectionType,
}

/// The connection type associated with a discovered peer.
#[derive(Debug, Clone)]
pub enum ConnectionType {
    /// A session has been established with the peer.
    Connected,
    /// An attempt to establish a session failed.
    CouldNotConnect,
    /// No session has been attempted.
    NotConnected,
}

impl From<kbucket::EntryView<NodeId, Enr>> for DiscoveredPeer {
    fn from(e: kbucket::EntryView<NodeId, Enr>) -> DiscoveredPeer {
        DiscoveredPeer {
            enr: e.node.value,
            connection_type: match e.status {
                NodeStatus::Connected => ConnectionType::Connected,
                NodeStatus::Disconnected => ConnectionType::NotConnected,
            },
        }
    }
}

impl<TSubstream> NetworkBehaviour for Discv5<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = DummyProtocolsHandler<TSubstream>;
    type OutEvent = Discv5Event;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        DummyProtocolsHandler::default()
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, _: PeerId, _: ConnectedPoint) {}

    fn inject_disconnected(&mut self, _: &PeerId, _: ConnectedPoint) {}

    fn inject_node_event(
        &mut self,
        _: PeerId,
        _ev: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        void::unreachable(_ev)
    }

    fn poll(
        &mut self,
        params: &mut PollParameters<'_>,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        return Async::NotReady;
    }
}

/// Event that can be produced by the `Discv5` behaviour.
#[derive(Debug)]
pub enum Discv5Event {
    /// Discovered nodes through discv5.
    Discovered {
        enr_id: NodeId,
        addresses: Vec<Multiaddr>,
        ty: ConnectionType,
    },
    EnrAdded {
        enr: Enr,
        replaced: Option<Enr>,
    },
    NodeInserted {
        node_id: NodeId,
        replaced: Option<NodeId>,
    },
}
