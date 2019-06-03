use crate::kbucket::{self, KBucketsTable, NodeStatus};
use crate::packet::NodeId;
use crate::query::{QueryConfig, QueryState, QueryStatePollOut};
use crate::session::SessionService;
use enr::Enr;
use fnv::{FnvHashMap, FnvHashSet};
use futures::prelude::*;
use futures::{prelude::*, stream};
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
use std::{borrow::Cow, error, marker::PhantomData, time::Duration};
use tokio_io::{AsyncRead, AsyncWrite};

mod query_info;

/// The number of results to return from a query. Defaults to the maximum number
/// of entries in a single k-bucket, i.e. the `k` parameter.
const BUCKET_SIZE: usize = 16;
/// The total time before marking an RPC request as failed.
const RPC_TIMEOUT: usize = 8;
/// The number of times to re-send an RPC request within the timeout.
const RPC_RETRIES: usize = 2;

type QueryId = usize;

pub struct Discv5<TSubstream> {
    events: SmallVec<[Discv5Event; 32]>,
    /// Storage of the ENR record for each node.
    kbuckets: KBucketsTable<NodeId, Enr>,

    /// All the iterative queries we are currently performing, with their ID. The last parameter
    /// is the list of accumulated providers for `GET_PROVIDERS` queries.
    active_queries: FnvHashMap<QueryId, QueryState<QueryInfo, NodeId>>,

    /// `α` in the Kademlia reference papers. Designates the maximum number of queries that we
    /// perform in parallel.
    parallelism: usize,

    /// List of peers we have established sessions with.
    connected_peers: FnvHashSet<NodeId>,

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
    /// `enr` is the `ENR` representing the local node. This contains node identifying information, such
    /// as IP addresses and ports which we wish to broadcast to other nodes via this discovery
    /// mechanism. The `ip` and `port` fields of the ENR will determine the ip/port that the discv5
    /// `Service` will listen on.
    pub fn new(enr: Enr, keypair: Keypair) -> io::Result<Self> {
        let parallelism = 3;

        let service = SessionService::new(enr.clone(), keypair)?;

        Ok(Discv5 {
            events: SmallVec::new(),
            kbuckets: KBucketsTable::new(enr.node_id.into(), Duration::from_secs(60)),
            active_queries: Default::default(),
            //pending_rpcs: SmallVec::with_capacity(parallelism),
            //next_query_id: QueryId(0),
            //values_providers: FnvHashMap::default(),
            //providing_keys: FnvHashSet::default(),
            //refresh_add_providers: Interval::new_interval(Duration::from_secs(60)).fuse(),     // TODO: constant
            parallelism,
            num_results: kbucket::MAX_NODES_PER_BUCKET,
            // rpc_timeout: Duration::from_secs(8),
            //add_provider: SmallVec::new(),
            service,
            marker: PhantomData,
        })
    }

    /// Adds a known ENR of a peer participating in Discv5 to the
    /// routing table.
    ///
    /// This allows prepopulating the Kademlia routing table with known
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
                        // TODO: Establish connection.  Look up known addresses
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
    pub fn find_node(&mut self, peer_id: PeerId) {
        self.start_query(QueryInfoInner::FindPeer(peer_id));
    }

    /// Internal function that starts a query.
    fn start_query(&mut self, target: QueryInfoInner) {
        let query_id = self.next_query_id;
        self.next_query_id.0 += 1;

        let target = QueryInfo {
            inner: target,
            untrusted_enrs: Default::default(),
        };

        let target_key = kbucket::Key::from(target.clone());

        let known_closest_peers = self
            .kbuckets
            .closest_keys(&target_key)
            .take(self.num_results);

        self.active_queries.insert(
            query_id,
            QueryState::new(QueryConfig {
                target,
                parallelism: self.parallelism,
                num_results: self.num_results,
                rpc_timeout: self.rpc_timeout,
                known_closest_peers,
            }),
        );
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
    Discovered(u64),
    EnrAdded {
        enr: Enr,
        replaced: Option<Enr>,
    },
}

/// Information about a query.
#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryInfo {
    /// What we are querying and why.
    inner: QueryInfoInner,
    /// Temporary addresses used when trying to reach nodes.
    untrusted_addresses: FnvHashMap<PeerId, SmallVec<[Multiaddr; 8]>>,
}

/// Additional information about the query.
#[derive(Debug, Clone, PartialEq, Eq)]
enum QueryInfoInner {
    /// The query was created for the Kademlia initialization process.
    Initialization {
        /// Hash we're targetting to insert ourselves in the k-buckets.
        target: NodeId,
    },

    /// The user requested a `FIND_PEER` query to be performed. It should be reported when finished.
    FindPeer(NodeId),
}
