use crate::kbucket;
use futures::prelude::*;
use smallvec::SmallVec;
use std::cmp::PartialEq;

#[derive(Debug)]
pub struct Query<TTarget, TNodeId> {
    /// Target we're looking for.
    target: TTarget,

    /// The target key we are looking for
    target_key: kbucket::Key<TTarget>,

    /// Stage of the query. See the documentation of `QueryStage`.
    stage: QueryStage,

    /// Ordered list of the peers closest to the result we're looking for.
    /// Entries that are `InProgress` shouldn't be removed from the list before they complete.
    /// Must never contain two entries with the same peer IDs.
    closest_peers: SmallVec<[(kbucket::Key<TNodeId>, QueryPeerState); 32]>,

    /// Allowed level of parallelism.
    parallelism: usize,

    /// Max iterations. Maximum times to re-request per node. The iteration can be linked
    /// to varying distances for FINDNODE queries.
    iterations: usize,

    /// Number of results to produce.
    num_results: usize,
}

/// Stage of the query.
#[derive(Debug)]
enum QueryStage {
    /// We are trying to find a closest node.
    Iterating {
        /// Number of successful query results in a row that didn't find any closer node.
        // TODO: this is not great, because we don't necessarily receive responses in the order
        //       we made the queries. It is possible that we query multiple far-away nodes in a
        //       row, and obtain results before the result of the closest nodes.
        no_closer_in_a_row: usize,
    },

    // We have found the closest node, and we are now pinging the nodes we know about.
    Frozen,
}

impl<TTarget, TNodeId> Query<TTarget, TNodeId>
where
    TTarget: Into<kbucket::Key<TTarget>> + Clone,
    TNodeId: Into<kbucket::Key<TNodeId>> + Eq,
{
    /// Creates a new query.
    pub fn new(
        target: TTarget,
        parallelism: usize,
        iterations: usize,
        num_results: usize,
        known_closest_peers: impl IntoIterator<Item = kbucket::Key<TNodeId>>,
    ) -> Self {
        let mut closest_peers: SmallVec<[_; 32]> = known_closest_peers
            .into_iter()
            .map(|key| (key, QueryPeerState::NotContacted))
            .take(num_results)
            .collect();

        let target_key = target.clone().into();
        closest_peers.sort_by_key(|e| target_key.distance(&e.0));
        closest_peers.dedup_by(|a, b| a.0 == b.0);

        Query {
            target: target,
            target_key,
            stage: QueryStage::Iterating {
                no_closer_in_a_row: 0,
            },
            closest_peers,
            parallelism,
            iterations,
            num_results,
        }
    }

    /// Returns the target of the query. Always the same as what was passed to `new()`.
    #[inline]
    pub fn target(&self) -> &TTarget {
        &self.target
    }

    /// Returns the target of the query. Always the same as what was passed to `new()`.
    ///
    /// You shouldn't modify the target in such a way that modifies the target of the query,
    /// otherwise logic errors will likely happen.
    #[inline]
    pub fn target_mut(&mut self) -> &mut TTarget {
        &mut self.target
    }

    /// After `poll()` returned `SendRpc`, this method should be called when the node sends back
    /// the result of the query.
    ///
    /// Note that if this query is a `FindValue` query and a node returns a record, feel free to
    /// immediately drop the query altogether and use the record.
    pub fn inject_rpc_result(
        &mut self,
        result_source: &impl PartialEq<TNodeId>,
        closer_peers: impl IntoIterator<Item = TNodeId>,
    ) {
        let num_closest = self.closest_peers.len();

        // Mark the peer's progress, the total nodes it has returned and it's current iteration
        for (peer_id, state) in self.closest_peers.iter_mut() {
            if result_source == peer_id.preimage() {
                if let state @ QueryPeerState::InProgress(_, _) = state {
                    if let QueryPeerState::InProgress(ref iteration, ref total) = state {
                        let total = total + num_closest;
                        if self.iterations == *iteration {
                            if total > 0 {
                                // mark the peer as succeeded
                                *state = QueryPeerState::Succeeded;
                            } else {
                                *state = QueryPeerState::Failed; // didn't return any peers
                            }
                        } else {
                            // set to re-iterate
                            *state = QueryPeerState::ToIterate(*iteration + 1, total)
                        }
                    }
                }
            }
        }

        // Add the entries in `closest_peers`.
        if let QueryStage::Iterating {
            ref mut no_closer_in_a_row,
        } = self.stage
        {
            let target = &self.target_key;

            // We increment now, and reset to 0 if we find a closer node.
            *no_closer_in_a_row += 1;

            for peer in closer_peers {
                let peer_key = peer.into();
                let peer_distance = target.distance(&peer_key);
                let insert_pos_start = self
                    .closest_peers
                    .iter()
                    .position(|(key, _)| target.distance(&key) >= peer_distance);

                if let Some(insert_pos_start) = insert_pos_start {
                    // We need to insert the element between `insert_pos_start` and
                    // `insert_pos_start + insert_pos_size`.
                    let insert_pos_size = self
                        .closest_peers
                        .iter()
                        .skip(insert_pos_start)
                        .position(|(key, _)| target.distance(&key) > peer_distance);

                    // Make sure we don't insert duplicates.
                    let mut iter_start = self.closest_peers.iter().skip(insert_pos_start);
                    let duplicate = if let Some(insert_pos_size) = insert_pos_size {
                        iter_start.take(insert_pos_size).any(|e| e.0 == peer_key)
                    } else {
                        iter_start.any(|e| e.0 == peer_key)
                    };

                    if !duplicate {
                        if insert_pos_start == 0 {
                            *no_closer_in_a_row = 0;
                        }
                        debug_assert!(self.closest_peers.iter().all(|e| e.0 != peer_key));
                        self.closest_peers
                            .insert(insert_pos_start, (peer_key, QueryPeerState::NotContacted));
                    }
                } else if num_closest < self.num_results {
                    debug_assert!(self.closest_peers.iter().all(|e| e.0 != peer_key));
                    self.closest_peers
                        .push((peer_key, QueryPeerState::NotContacted));
                }
            }
        }

        // Check for duplicates in `closest_peers`.
        debug_assert!(self.closest_peers.windows(2).all(|w| w[0].0 != w[1].0));

        let num_closest_new = self.closest_peers.len();

        // Termination condition: If at least `self.parallelism` * `self.iterations` consecutive
        // responses yield no peer closer to the target and either no new peers
        // were discovered or the number of discovered peers reached the desired
        // number of results, then the query is considered complete.
        if let QueryStage::Iterating { no_closer_in_a_row } = self.stage {
            if no_closer_in_a_row >= self.parallelism * self.iterations
                && (num_closest == num_closest_new || num_closest_new >= self.num_results)
            {
                self.stage = QueryStage::Frozen;
            }
        }
    }

    /// Returns the list of peers for which we are waiting for an answer.
    pub fn waiting(&self) -> impl Iterator<Item = &TNodeId> {
        self.closest_peers
            .iter()
            .filter(|(_, state)| match state {
                QueryPeerState::InProgress(_, _) => true,
                QueryPeerState::ToIterate(_, _) => false,
                QueryPeerState::NotContacted => false,
                QueryPeerState::Succeeded => false,
                QueryPeerState::Failed => false,
            })
            .map(|(key, _)| key.preimage())
    }

    /// Returns true if we are waiting for a query answer from that peer.
    ///
    /// After `poll()` returned `SendRpc`, this function will return `true`.
    pub fn is_waiting(&self, id: &impl PartialEq<TNodeId>) -> bool {
        self.waiting().any(|peer_id| id == peer_id)
    }

    /// After `poll()` returned `SendRpc`, this function should be called if we were unable to
    /// reach the peer, or if an error of some sort happened. No further iterations will occur for
    /// this peer.
    ///
    /// Has no effect if the peer ID is not relevant to the query, so feel free to call this
    /// function whenever an error happens on the network.
    ///
    /// After this function returns, you should call `poll()` again.
    pub fn inject_rpc_error(&mut self, id: &TNodeId) {
        let state = self.closest_peers.iter_mut().find_map(|(peer_id, state)| {
            if peer_id.preimage() == id {
                Some(state)
            } else {
                None
            }
        });

        match state {
            Some(state @ &mut QueryPeerState::InProgress(_, _)) => *state = QueryPeerState::Failed,
            Some(&mut QueryPeerState::ToIterate(_, _)) => (),
            Some(&mut QueryPeerState::NotContacted) => (),
            Some(&mut QueryPeerState::Succeeded) => (),
            Some(&mut QueryPeerState::Failed) => (),
            None => (),
        }
    }

    /// Polls this individual query.
    pub fn poll(&mut self) -> Async<QueryPollOut<'_, TTarget, TNodeId>> {
        // While iterating over peers, count the number of queries currently being processed.
        // This is used to not go over the limit of parallel requests.
        // If this is still 0 at the end of the function, that means the query is finished.
        let mut active_counter = 0;

        // While iterating over peers, count the number of queries in a row (from closer to further
        // away from target) that are in the succeeded state.
        let mut succeeded_counter = Some(0);

        // Extract `self.num_results` to avoid borrowing errors with closures.
        let num_results = self.num_results;

        for &mut (ref node_id, ref mut state) in self.closest_peers.iter_mut() {
            // Re-send the request to a given peer.
            // re-requests to the same peer happen beyond parallelism.
            if let state @ QueryPeerState::ToIterate(_, _) = state {
                if let QueryPeerState::ToIterate(ref iteration, ref total) = state {
                    *state = QueryPeerState::InProgress(*iteration, *total);
                    return Async::Ready(QueryPollOut::SendRpc {
                        node_id: node_id.preimage(),
                        iteration: *iteration,
                        query_target: &self.target,
                    });
                }
            }

            if let QueryPeerState::InProgress(_, _) = state {
                succeeded_counter = None;
                active_counter += 1
            }

            if let QueryPeerState::Succeeded = state {
                if let Some(ref mut cnt) = succeeded_counter {
                    *cnt += 1;
                    // If we have enough results; the query is done.
                    if *cnt >= num_results {
                        return Async::Ready(QueryPollOut::Finished);
                    }
                }
            }

            if let QueryPeerState::NotContacted = state {
                let connect = match self.stage {
                    QueryStage::Frozen => false,
                    QueryStage::Iterating { .. } => active_counter < self.parallelism,
                };
                if connect {
                    *state = QueryPeerState::InProgress(1, 0);
                    return Async::Ready(QueryPollOut::SendRpc {
                        node_id: node_id.preimage(),
                        iteration: 0,
                        query_target: &self.target,
                    });
                } else {
                    // The peer is among the `num_results` closest and still
                    // needs to be contacted, but the query is currently at
                    // capacity w.r.t. the allowed parallelism.
                    return Async::NotReady;
                }
            }
        }

        // If we don't have any query in progress, return `Finished` as we don't have
        // anything more we can do.
        if active_counter > 0 {
            Async::NotReady
        } else {
            Async::Ready(QueryPollOut::Finished)
        }
    }

    /// Consumes the query and returns the target and known closest peers.
    ///
    /// > **Note**: This can be called at any time, but you normally only do that once the query
    /// >           is finished.
    pub fn into_target_and_closest_peers(self) -> (TTarget, impl Iterator<Item = TNodeId>) {
        let closest = self
            .closest_peers
            .into_iter()
            .filter_map(|(node_id, state)| {
                if let QueryPeerState::Succeeded = state {
                    Some(node_id.into_preimage())
                } else {
                    None
                }
            })
            .take(self.num_results);
        (self.target, closest)
    }

    /// Consumes the query and returns the known closest peers.
    ///
    /// > **Note**: This can be called at any time, but you normally only do that once the query
    /// >           is finished.
    pub fn into_closest_peers(self) -> impl Iterator<Item = TNodeId> {
        self.into_target_and_closest_peers().1
    }
}

/// Outcome of polling a query.
#[derive(Debug, Clone)]
pub enum QueryPollOut<'a, TTarget, TNodeId> {
    /// The query is finished.
    ///
    /// If this is a `FindValue` query, the user is supposed to extract the record themselves from
    /// any RPC result sent by a remote. If the query finished without that happening, this means
    /// that we didn't find any record.
    ///
    /// If this is a `FindNode` query, you can call `into_closest_peers` in order to obtain the
    /// result.
    Finished,

    /// We need to send an RPC query to the given peer.
    ///
    /// The RPC query to send can be derived from the target of the query.
    ///
    /// After this has been returned, you should call either `inject_rpc_result` or
    /// `inject_rpc_error` at a later point in time.
    SendRpc {
        /// The peer to send the RPC query to.
        node_id: &'a TNodeId,
        /// The number of times this rpc has been requested for this peer.
        iteration: usize,
        /// A reminder of the query target. Same as what you obtain by calling `target()`.
        query_target: &'a TTarget,
    },
}

type Iteration = usize;

/// State of peer in the context of a query.
#[derive(Debug)]
enum QueryPeerState {
    /// We haven't tried contacting the node.
    NotContacted,
    /// Waiting for an answer from the node to our RPC query. Contains the number of times we
    /// have requested the node and the number of peers it has returned in total.
    InProgress(Iteration, usize),
    ///
    ToIterate(Iteration, usize),
    /// Contacted, with insufficient results, re-iterating.
    /// We successfully reached the node.
    Succeeded,
    /// We tried to reach the node but failed, or the node didn't respond with any results.
    Failed,
}

/*
#[cfg(test)]
mod tests {
    use super::{kbucket, Query, QueryPollOut};
    use futures::{self, try_ready, prelude::*};
    use libp2p_core::PeerId;
    use std::{iter, time::Duration, sync::Arc, sync::Mutex, thread};
    use tokio;

    #[test]
    fn start_by_sending_rpc_to_known_peers() {
        let random_id = PeerId::random();
        let random_key = kbucket::Key::new(random_id.clone());
        let target = PeerId::random();

        let mut query = QueryState::new(QueryConfig {
            target,
            known_closest_peers: iter::once(random_key),
            parallelism: 3,
            num_results: 100,
            rpc_timeout: Duration::from_secs(10),
        });

        tokio::run(futures::future::poll_fn(move || {
            match try_ready!(Ok(query.poll())) {
                QueryStatePollOut::SendRpc { peer_id, .. } if peer_id == &random_id => {
                    Ok(Async::Ready(()))
                }
                _ => panic!(),
            }
        }));
    }

    #[test]
    fn continue_second_result() {
        let random_id = PeerId::random();
        let random_key = kbucket::Key::from(random_id.clone());
        let random_id2 = PeerId::random();
        let target = PeerId::random();

        let query = Arc::new(Mutex::new(QueryState::new(QueryConfig {
            target,
            known_closest_peers: iter::once(random_key),
            parallelism: 3,
            num_results: 100,
            rpc_timeout: Duration::from_secs(10),
        })));

        // Let's do a first polling round to obtain the `SendRpc` request.
        tokio::run(futures::future::poll_fn({
            let random_id = random_id.clone();
            let query = query.clone();
            move || {
                match try_ready!(Ok(query.lock().unwrap().poll())) {
                    QueryStatePollOut::SendRpc { peer_id, .. } if peer_id == &random_id => {
                        Ok(Async::Ready(()))
                    }
                    _ => panic!(),
                }
            }
        }));

        // Send the reply.
        query.lock().unwrap().inject_rpc_result(&random_id, iter::once(random_id2.clone()));

        // Second polling round to check the second `SendRpc` request.
        tokio::run(futures::future::poll_fn({
            let query = query.clone();
            move || {
                match try_ready!(Ok(query.lock().unwrap().poll())) {
                    QueryStatePollOut::SendRpc { peer_id, .. } if peer_id == &random_id2 => {
                        Ok(Async::Ready(()))
                    }
                    _ => panic!(),
                }
            }
        }));
    }

    #[test]
    fn timeout_works() {
        let random_id = PeerId::random();
        let random_key = kbucket::Key::from(random_id.clone());

        let query = Arc::new(Mutex::new(QueryState::new(QueryConfig {
            target: PeerId::random(),
            known_closest_peers: iter::once(random_key),
            parallelism: 3,
            num_results: 100,
            rpc_timeout: Duration::from_millis(100),
        })));

        // Let's do a first polling round to obtain the `SendRpc` request.
        tokio::run(futures::future::poll_fn({
            let random_id = random_id.clone();
            let query = query.clone();
            move || {
                match try_ready!(Ok(query.lock().unwrap().poll())) {
                    QueryStatePollOut::SendRpc { peer_id, .. } if peer_id == &random_id => {
                        Ok(Async::Ready(()))
                    }
                    _ => panic!(),
                }
            }
        }));

        // Wait for a bit.
        thread::sleep(Duration::from_millis(200));

        // Second polling round to check the timeout.
        tokio::run(futures::future::poll_fn({
            let query = query.clone();
            move || {
                match try_ready!(Ok(query.lock().unwrap().poll())) {
                    QueryStatePollOut::CancelRpc { peer_id, .. } if peer_id == &random_id => {
                        Ok(Async::Ready(()))
                    }
                    _ => panic!(),
                }
            }
        }));

        // Third polling round for finished.
        tokio::run(futures::future::poll_fn({
            let query = query.clone();
            move || {
                match try_ready!(Ok(query.lock().unwrap().poll())) {
                    QueryStatePollOut::Finished => {
                        Ok(Async::Ready(()))
                    }
                    _ => panic!(),
                }
            }
        }));
    }
}
*/
