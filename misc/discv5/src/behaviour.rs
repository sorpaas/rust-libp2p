//! The libp2p behaviour which implements [discovery v5](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md).

//TODO: Document the behaviour

use self::ip_vote::IpVote;
use self::query_info::{QueryInfo, QueryType};
use crate::kbucket::{self, EntryRefView, KBucketsTable, NodeStatus};
use crate::query::{Query, QueryConfig, QueryState, ReturnPeer};
use crate::rpc;
use crate::service::MAX_PACKET_SIZE;
use crate::session_service::{SessionEvent, SessionService};
use enr::{Enr, NodeId};
use fnv::FnvHashMap;
use futures::prelude::*;
use libp2p_core::identity::Keypair;
use libp2p_core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    protocols_handler::{DummyProtocolsHandler, ProtocolsHandler},
    PeerId,
};
use log::{debug, error, trace, warn};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::{marker::PhantomData, time::Duration};
use tokio::timer::Interval;
use tokio_io::{AsyncRead, AsyncWrite};

mod ip_vote;
mod query_info;
mod test;

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

    /// Events yielded by this behaviour.
    events: SmallVec<[Discv5Event; 32]>,

    /// Abstract the NodeId from libp2p. For all known ENR's we keep a mapping of PeerId to NodeId.
    known_peer_ids: HashMap<PeerId, NodeId>,

    /// Storage of the ENR record for each node.
    kbuckets: KBucketsTable<NodeId, Enr>,

    /// All the iterative queries we are currently performing, with their ID. The last parameter
    /// is the list of accumulated providers for `GET_PROVIDERS` queries.
    active_queries: FnvHashMap<QueryId, Query<QueryInfo, NodeId>>,

    /// RPC requests that have been sent and are awaiting a response. Some requests are linked to a
    /// query.
    active_rpc_requests: FnvHashMap<RpcRequest, (Option<QueryId>, rpc::Request)>,

    /// Keeps track of the number of responses received from a NODES response.
    active_nodes_responses: HashMap<NodeId, usize>,

    /// A map of votes nodes have made about our external IP address. We accept the majority.
    ip_votes: IpVote,

    /// List of peers we have established sessions with and an interval for when to send a PING.
    connected_peers: HashMap<NodeId, Interval>,

    /// The configuration for iterative queries.
    query_config: QueryConfig,

    /// Identifier for the next query that we start.
    next_query_id: QueryId,

    /// Main discv5 UDP service that establishes sessions with peers.
    service: SessionService,

    /// The time between pings to ensure connectivity amongst connected nodes.
    ping_delay: Duration,

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
            known_peer_ids: HashMap::new(),
            kbuckets: KBucketsTable::new(
                local_enr.node_id().clone().into(),
                Duration::from_secs(60),
            ),
            active_queries: Default::default(),
            active_rpc_requests: Default::default(),
            active_nodes_responses: HashMap::new(),
            ip_votes: IpVote::new(),
            connected_peers: Default::default(),
            next_query_id: 0,
            query_config,
            service,
            ping_delay: Duration::from_secs(300),
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
        // add to the known_peer_ids mapping
        self.known_peer_ids
            .insert(enr.peer_id().clone(), enr.node_id().clone());
        let key = kbucket::Key::from(enr.node_id().clone());
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
                        // Try and establish a connection
                        self.send_ping(&disconnected.into_preimage());
                    }
                }
                return;
            }
            kbucket::Entry::SelfEntry => return,
        };
    }

    pub fn local_enr(&self) -> &Enr {
        &self.local_enr
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

    // private functions //

    /// Processes an RPC request from a peer. Requests respond to the recieved socket address,
    /// rather than the IP of the known ENR.
    fn handle_rpc_request(
        &mut self,
        src: SocketAddr,
        node_id: NodeId,
        rpc_id: u64,
        req: rpc::Request,
    ) {
        // check for the ENR for the sender.
        let enr = match self.kbuckets.entry(&node_id.clone().into()) {
            kbucket::Entry::Present(ref mut entry, _) => entry.value().clone(),
            kbucket::Entry::Pending(ref mut entry, _) => entry.value().clone(),
            _ => {
                error!("Received a message from an unknown peer");
                return;
            }
        };
        match req {
            rpc::Request::FindNode { distance } => {
                // if the distance is 0 send our local ENR
                if distance == 0 {
                    let res = rpc::ProtocolMessage {
                        id: rpc_id,
                        body: rpc::RpcType::Response(rpc::Response::Nodes {
                            total: 1,
                            nodes: vec![self.local_enr.clone()],
                        }),
                    };
                    let _ = self
                        .service
                        .send_message(&enr, res, Some(src))
                        .map_err(|e| warn!("Failed to send a FINDNODES response. Error: {:?}", e));
                } else {
                    self.send_nodes_response(src, rpc_id, &enr, distance);
                }
            }
            rpc::Request::Ping { enr_seq } => {
                // check if we need to update the known ENR
                if enr.seq < enr_seq {
                    self.request_enr(&node_id);
                }
                // build the PONG response
                let message = rpc::ProtocolMessage {
                    id: rpc_id,
                    body: rpc::RpcType::Response(rpc::Response::Ping {
                        enr_seq: self.local_enr.seq,
                        ip: src.ip(),
                        port: src.port(),
                    }),
                };
                let _ = self
                    .service
                    .send_message(&enr, message, Some(src))
                    .map_err(|e| warn!("Failed to send rpc request. Error: {:?}", e));
            }
            _ => {} //TODO: Implement all RPC methods
        }
    }

    /// Processes an RPC response from a peer.
    fn handle_rpc_response(&mut self, node_id: NodeId, rpc_id: u64, res: rpc::Response) {
        // verify we know of the rpc_id
        let req = RpcRequest(rpc_id, node_id.clone());
        if let Some((query_id, request)) = self.active_rpc_requests.remove(&req) {
            if !res.match_request(&request) {
                warn!(
                    "Node gave an incorrect response type. Ignoring response from node: {}",
                    node_id
                );
                return;
            }
            match res {
                rpc::Response::Nodes { total, mut nodes } => {
                    if let Some(query_id) = query_id {
                        let mut current_response = self
                            .active_nodes_responses
                            .remove(&node_id)
                            .unwrap_or_else(|| 1);
                        // Currently a maximum of 16 peers can be returned. Datagrams have a max
                        // size of 1280 and ENR's have a max size of 300 bytes. There should be no
                        // more than 5 responses, to return 16 peers.
                        if total < 5 && (current_response as u64) < total {
                            current_response += 1;
                            self.active_rpc_requests
                                .insert(req, (Some(query_id), request.clone()));
                            self.active_nodes_responses
                                .insert(node_id.clone(), current_response);
                        } else {
                            self.active_nodes_responses.remove(&node_id);
                        }
                        // filter out any nodes that are not of the correct distance
                        // TODO: If a swarm peer reputation is built - downvote the peer if all
                        // peers do not have the correct distance.
                        let peer_key: kbucket::Key<NodeId> = node_id.clone().into();
                        let distance_requested = match request {
                            rpc::Request::FindNode { distance } => distance,
                            _ => unreachable!(),
                        };
                        nodes.retain(|enr| {
                            peer_key.log2_distance(&enr.node_id().clone().into())
                                == Some(distance_requested)
                        });
                        self.discovered(query_id, &node_id, nodes);
                    }
                }
                rpc::Response::Ping { enr_seq, ip, port } => {
                    let socket = SocketAddr::new(ip, port);
                    self.ip_votes.insert(node_id.clone(), socket);
                    if self.ip_votes.majority() != self.local_enr.udp_socket() {
                        debug!("Local IP Address updated to: {:?}", socket);
                        let _ = self.local_enr.set_udp_socket(socket, &self.keypair);
                    }

                    // check if we need to request a new ENR
                    if let Some(enr) = self.find_enr(&node_id) {
                        if enr.seq < enr_seq {
                            // request an ENR update
                            let req = rpc::Request::FindNode { distance: 0 };
                            self.send_rpc_request(&node_id, req, None);
                        }
                    }
                }
                _ => {} //TODO: Implement all RPC methods
            }
        }
    }

    // Send RPC Requests //

    /// Sends a PING request to a node.
    fn send_ping(&mut self, node_id: &NodeId) {
        let req = rpc::Request::Ping {
            enr_seq: self.local_enr.seq,
        };
        self.send_rpc_request(&node_id, req, None);
    }

    /// Request an external node's ENR.
    fn request_enr(&mut self, node_id: &NodeId) {
        let req = rpc::Request::FindNode { distance: 0 };
        self.send_rpc_request(&node_id, req, None);
    }

    /// Sends a NODES response, given a list of found ENR's. This function splits the nodes up
    /// into multiple responses to ensure the response stays below the maximum packet size.
    fn send_nodes_response(
        &mut self,
        dst: SocketAddr, // overwrites the ENR IP - we resend to the IP we received the request from
        rpc_id: u64,
        enr: &Enr,
        distance: u64,
    ) {
        trace!("Sending FINDNODES response");
        let nodes: Vec<EntryRefView<NodeId, Enr>> = self
            .kbuckets
            .nodes_by_distance(distance)
            .into_iter()
            .filter(|entry| entry.node.key.preimage() != enr.node_id())
            .collect();
        // if there are no nodes, send an empty response
        if nodes.is_empty() {
            let response = rpc::ProtocolMessage {
                id: rpc_id,
                body: rpc::RpcType::Response(rpc::Response::Nodes {
                    total: 1u64,
                    nodes: Vec::new(),
                }),
            };
            let _ = self
                .service
                .send_message(enr, response, Some(dst))
                .map_err(|e| warn!("Failed to send a FINDNODES response. Error: {:?}", e));
        } else {
            // build the NODES response
            let mut to_send_nodes: Vec<Vec<Enr>> = Vec::new();
            let mut total_size = 0;
            let mut rpc_index = 0;
            to_send_nodes.push(Vec::new());
            for entry in nodes.into_iter() {
                if entry.node.value.size() + total_size < MAX_PACKET_SIZE - 80 {
                    total_size += entry.node.value.size();
                    to_send_nodes[rpc_index].push(entry.node.value.clone());
                } else {
                    total_size = entry.node.value.size();
                    to_send_nodes.push(vec![entry.node.value.clone()]);
                    rpc_index += 1;
                }
            }

            let responses: Vec<rpc::ProtocolMessage> = to_send_nodes
                .into_iter()
                .map(|nodes| rpc::ProtocolMessage {
                    id: rpc_id,
                    body: rpc::RpcType::Response(rpc::Response::Nodes {
                        total: (rpc_index + 1) as u64,
                        nodes,
                    }),
                })
                .collect();

            for response in responses {
                let _ = self
                    .service
                    .send_message(enr, response, Some(dst))
                    .map_err(|e| warn!("Failed to send a FINDNODES response. Error: {:?}", e));
            }
        }
    }

    /// Constructs and sends a request RPC to the session service given a `QueryInfo`.
    fn send_rpc_query(
        &mut self,
        query_id: QueryId,
        query_info: QueryInfo,
        return_peer: &ReturnPeer<NodeId>,
    ) {
        let node_id = return_peer.node_id.clone();
        trace!(
            "Sending query. Iteration: {}, NodeId: {}",
            return_peer.iteration,
            node_id
        );

        let req = match query_info.into_rpc_request(return_peer) {
            Ok(r) => r,
            Err(e) => {
                //dst node is local_key, report failure
                error!("Send RPC: {}", e);
                if let Some(query) = self.active_queries.get_mut(&query_id) {
                    query.on_failure(&node_id);
                }
                return;
            }
        };

        self.send_rpc_request(&node_id, req, Some(query_id));
    }

    /// Sends generic RPC requests. Each request gets added to known outputs, awaiting a response.
    fn send_rpc_request(&mut self, node_id: &NodeId, req: rpc::Request, query_id: Option<QueryId>) {
        // find the destination ENR
        if let Some(dst_enr) = self.find_enr(&node_id) {
            // Generate a random rpc_id which is matched per node id
            let id: u64 = rand::random();
            let rpc_request = RpcRequest(id, node_id.clone());

            match self.service.send_message(
                &dst_enr,
                rpc::ProtocolMessage {
                    id,
                    body: rpc::RpcType::Request(req.clone()),
                },
                None,
            ) {
                Ok(_) => {
                    self.active_rpc_requests
                        .insert(rpc_request, (query_id, req));
                }
                Err(_) => {
                    if let Some(query_id) = query_id {
                        if let Some(query) = self.active_queries.get_mut(&query_id) {
                            query.on_failure(&node_id);
                        }
                    }
                }
            }
        } else {
            warn!(
                "Request not sent. Failed to find ENR for Node: {:?}",
                node_id
            );
        }
    }

    /// Returns an ENR if one is known for the given NodeId.
    fn find_enr(&mut self, node_id: &NodeId) -> Option<Enr> {
        // check if we know this node id in our routing table
        let key = kbucket::Key::from(node_id.clone());
        if let kbucket::Entry::Present(mut entry, _) = self.kbuckets.entry(&key) {
            return Some(entry.value().clone());
        }
        // check the untrusted addresses for ongoing queries
        for query in self.active_queries.values() {
            if let Some(enr) = query
                .target()
                .untrusted_enrs
                .iter()
                .find(|v| v.node_id() == node_id)
            {
                return Some(enr.clone());
            }
        }
        None
    }

    /// Internal function that starts a query.
    fn start_query(&mut self, query_type: QueryType) {
        let query_id = self.next_query_id;
        self.next_query_id += 1;

        let target = QueryInfo {
            query_type,
            untrusted_enrs: Default::default(),
        };

        // How many times to call the rpc per node.
        // FINDNODE requires multiple iterations as it requests a specific distance.
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
    fn discovered(&mut self, query_id: QueryId, source: &NodeId, peers: Vec<Enr>) {
        let local_id = self.local_enr.node_id();
        let others_iter = peers.into_iter().filter(|p| p.node_id() != local_id);

        for peer in others_iter.clone() {
            self.events.push(Discv5Event::Discovered {
                enr_id: peer.node_id().clone(),
                addresses: peer.multiaddr().clone(),
            });

            // If any of the discovered nodes are in the routing table, and there contains an older ENR, update it.
            let key = kbucket::Key::from(peer.node_id().clone());
            if let kbucket::Entry::Present(mut entry, _) = self.kbuckets.entry(&key) {
                if entry.value().seq < peer.seq {
                    trace!("Enr updated: {}", peer);
                    *entry.value() = peer.clone();
                }
            }
        }

        if let Some(query) = self.active_queries.get_mut(&query_id) {
            for peer in others_iter.clone() {
                if query
                    .target_mut()
                    .untrusted_enrs
                    .iter()
                    .position(|e| e.node_id() == peer.node_id())
                    .is_none()
                {
                    query.target_mut().untrusted_enrs.push(peer.clone());
                }
            }
            query.on_success(source, others_iter.map(|kp| kp.node_id().clone()))
        }
    }

    /// Update the connection status of a node in the routing table.
    fn connection_updated(&mut self, node_id: NodeId, enr: Option<Enr>, new_status: NodeStatus) {
        let key = kbucket::Key::from(node_id.clone());
        // add the known PeerId
        if let Some(enr_copy) = enr.clone() {
            self.known_peer_ids
                .insert(enr_copy.peer_id(), enr_copy.node_id().clone());
        }
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
                                    .contains_key(disconnected.preimage()));
                                self.send_ping(&disconnected.into_preimage());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// The equivalent of libp2p `inject_connected()` for a udp session. We have no stream, but a
    /// session key-pair has been negotiated.
    fn inject_session_established(&mut self, node_id: NodeId, enr: Enr) {
        self.known_peer_ids.insert(enr.peer_id(), node_id.clone());
        self.connection_updated(node_id.clone(), Some(enr), NodeStatus::Connected);
        // send an initial ping and start the ping interval
        self.send_ping(&node_id);
        let interval = Interval::new_interval(self.ping_delay);
        self.connected_peers.insert(node_id, interval);
    }

    /// A session could not be established or an RPC request timed-out (after a few retries).
    fn rpc_failure(&mut self, node_id: NodeId, failed_rpc_id: RpcId) {
        let req = RpcRequest(failed_rpc_id, node_id.clone());

        if let Some((Some(query_id), _)) = self.active_rpc_requests.get(&req) {
            if let Some(query) = self.active_queries.get_mut(&query_id) {
                query.on_failure(&node_id);
            }
        }

        // report the node as being disconnected.
        self.connection_updated(node_id.clone(), None, NodeStatus::Disconnected);
        self.connected_peers.remove(&node_id);
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
        // Addresses are ordered by decreasing likelyhood of connectivity, so start with
        // the addresses of that peer in the k-buckets.

        if let Some(node_id) = self.known_peer_ids.get(peer_id) {
            let key = kbucket::Key::from(node_id.clone());
            let mut out_list =
                if let kbucket::Entry::Present(mut entry, _) = self.kbuckets.entry(&key) {
                    entry.value().multiaddr().to_vec()
                } else {
                    Vec::new()
                };

            // ENR's may have multiple Multiaddrs. The multi-addr associated with the UDP
            // port is removed, which is assumed to be associated with the discv5 protocol (and
            // therefore irrelevant for other libp2p components).
            out_list.retain(|addr| {
                addr.iter()
                    .find(|v| match v {
                        Protocol::Udp(_) => true,
                        _ => false,
                    })
                    .is_none()
            });

            out_list
        } else {
            // PeerId is not known
            Vec::new()
        }
    }

    // ignore libp2p connections/streams
    fn inject_connected(&mut self, _: PeerId, _: ConnectedPoint) {}

    // ignore libp2p connections/streams
    fn inject_disconnected(&mut self, _: &PeerId, _: ConnectedPoint) {}

    // no libp2p discv5 events - event originate from the session_service.
    fn inject_node_event(
        &mut self,
        _: PeerId,
        _ev: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        void::unreachable(_ev)
    }

    fn poll(
        &mut self,
        _params: &mut PollParameters<'_>,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        loop {
            // Drain queued events
            if !self.events.is_empty() {
                return Async::Ready(NetworkBehaviourAction::GenerateEvent(self.events.remove(0)));
            }
            self.events.shrink_to_fit();

            // Process events from the session service
            while let Async::Ready(event) = self.service.poll() {
                match event {
                    SessionEvent::Established(node_id, enr) => {
                        self.inject_session_established(node_id, enr);
                    }
                    SessionEvent::Message {
                        src_id,
                        src,
                        message,
                    } => match message.body {
                        rpc::RpcType::Request(req) => {
                            self.handle_rpc_request(src, src_id, message.id, req);
                        }
                        rpc::RpcType::Response(res) => {
                            self.handle_rpc_response(src_id, message.id, res)
                        }
                    },
                    SessionEvent::WhoAreYouRequest {
                        src,
                        src_id,
                        auth_tag,
                    } => {
                        // check what our latest known ENR is for this node.
                        if let Some(known_enr) = self.find_enr(&src_id) {
                            self.service.send_whoareyou(
                                src,
                                &src_id,
                                known_enr.seq,
                                Some(known_enr.clone()),
                                auth_tag,
                            );
                        } else {
                            // do not know of this peer
                            debug!("NodeId unknown, requesting ENR. NodeId: {}", src_id);
                            self.service.send_whoareyou(src, &src_id, 0, None, auth_tag)
                        }
                    }
                    SessionEvent::RequestFailed(node_id, rpc_id) => {
                        self.rpc_failure(node_id, rpc_id);
                    }
                }
            }

            // Drain applied pending entries from the routing table.
            if let Some(entry) = self.kbuckets.take_applied_pending() {
                let event = Discv5Event::NodeInserted {
                    node_id: entry.inserted.into_preimage(),
                    replaced: entry.evicted.map(|n| n.key.into_preimage()),
                };
                return Async::Ready(NetworkBehaviourAction::GenerateEvent(event));
            }

            // Handle active queries

            // If iterating finds a query that is finished, stores it here and stops looping.
            let mut finished_query = None;
            // If a query is waiting for an rpc to send, store it here and stop looping.
            let mut waiting_query = None;

            for (&query_id, query) in self.active_queries.iter_mut() {
                let target = query.target().clone();
                match query.next() {
                    QueryState::Finished => {
                        finished_query = Some(query_id);
                        break;
                    }
                    QueryState::Waiting(Some(return_peer)) => {
                        // break the loop to send the rpc request
                        waiting_query = Some((query_id, target, return_peer));
                        break;
                    }
                    QueryState::Waiting(None) | QueryState::WaitingAtCapacity => (),
                }
            }

            if let Some((query_id, target, return_peer)) = waiting_query {
                self.send_rpc_query(query_id, target, &return_peer);
            } else if let Some(finished_query) = finished_query {
                let result = self
                    .active_queries
                    .remove(&finished_query)
                    .expect("finished_query was gathered when iterating active_queries; QED.")
                    .into_result();

                match result.target.query_type {
                    QueryType::FindNode(node_id) => {
                        let event = Discv5Event::FindNodeResult {
                            key: node_id,
                            closer_peers: result.closest_peers.collect(),
                        };
                        return Async::Ready(NetworkBehaviourAction::GenerateEvent(event));
                    }
                }
            } else {
                // check for ping intervals
                let mut to_send_ping = Vec::new();
                for (node_id, interval) in self.connected_peers.iter_mut() {
                    while let Ok(Async::Ready(_)) = interval.poll() {
                        to_send_ping.push(node_id.clone());
                    }
                }
                to_send_ping.dedup();
                for id in to_send_ping.into_iter() {
                    debug!("Sending PING to: {}", id);
                    self.send_ping(&id);
                }

                return Async::NotReady;
            }
        }
    }
}

// TODO: Potentially abstract ENR NodeId and use PeerId's for outer interface.
/// Event that can be produced by the `Discv5` behaviour.
#[derive(Debug)]
pub enum Discv5Event {
    /// Discovered nodes through discv5.
    Discovered {
        enr_id: NodeId,
        addresses: Vec<Multiaddr>,
    },
    EnrAdded {
        enr: Enr,
        replaced: Option<Enr>,
    },
    NodeInserted {
        node_id: NodeId,
        replaced: Option<NodeId>,
    },
    /// Result of a `FIND_NODE` iterative query.
    FindNodeResult {
        /// The key that we looked for in the query.
        key: NodeId,
        /// List of peers ordered from closest to furthest away.
        closer_peers: Vec<NodeId>,
    },
}
