use crate::kbucket::{self, KBucketsTable, NodeStatus};
use crate::packet::NodeId;
use enr::Enr;
use fnv::{FnvHashMap, FnvHashSet};
use futures::prelude::*;
use futures::{prelude::*, stream};
use libp2p_core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p_core::{
    protocols_handler::{DummyProtocolsHandler, ProtocolsHandler},
    Multiaddr, PeerId,
};
use smallvec::SmallVec;
use std::{borrow::Cow, error, marker::PhantomData, time::Duration};
use tokio_io::{AsyncRead, AsyncWrite};

pub struct Discv5<TSubstream> {
    // events: SmallVec<[NetworkBehaviourAction<In, Out>; 32]>,
    /// Storage of the ENR record for each node.
    kbuckets: KBucketsTable<NodeId, Enr>,

    /// `α` in the Kademlia reference papers. Designates the maximum number of queries that we
    /// perform in parallel.
    parallelism: usize,

    /// The number of results to return from a query. Defaults to the maximum number
    /// of entries in a single k-bucket, i.e. the `k` parameter.
    num_results: usize,

    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
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
}
