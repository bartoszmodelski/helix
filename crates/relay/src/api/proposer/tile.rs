use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crossbeam_channel::{Receiver, Sender};
use flux::{
    spine::SpineAdapter,
    tile::Tile,
    timing::{Duration, Instant, Repeater},
};
use flux_network::Token;
use flux_utils::SharedVector;
use helix_common::{
    GetHeaderTrace, Route, RouterConfig,
    api::{builder_api::BuilderGetValidatorsResponseEntry, proposer_api::GetHeaderParams},
    decoder::{Encoding, HEADER_SSZ},
    utils::extract_request_id,
};
use helix_types::Slot;
use rustc_hash::FxHashMap;
use ssz::Encode;
use tracing::{debug, error, info_span};

use super::{
    CONSENSUS_VERSION_HEADER, ProposerApi, ProposerApiError,
    get_header::{SignedBidCache, TimeoutGuard},
};
use crate::{
    HelixSpine,
    api::{
        Api,
        router::count_request_timeout,
        server::{ApiServer, Inbound, Responder},
        service::API_REQUEST_TIMEOUT,
    },
    auctioneer::{GetHeaderResult, Reply},
    housekeeper::SlotUpdate,
    spine::messages::{ProposerRequestKind, SlotMsg},
};

const JSON: (&str, &str) = ("content-type", "application/json");
/// Answers written per turn. The rest wait a turn, so that a burst of answers does not
/// keep the tile from reading new requests and releasing held ones on time.
const MAX_ANSWERS_PER_TURN: usize = 32;
const LIMITER_PRUNE_INTERVAL_SECS: u64 = 60;

/// A `get_header` request between its arrival and its answer. Dropping it unanswered
/// reports the caller as having given up, through `guard`.
struct PendingHeader<A: Api> {
    id: u64,
    responder: Responder,
    params: GetHeaderParams,
    encoding: Encoding,
    peer: SocketAddr,
    ip_addr: Option<IpAddr>,
    is_mev_boost: bool,
    user_agent: Option<String>,
    trace: GetHeaderTrace,
    received: Instant,
    /// When to ask the auctioneer; `None` once asked.
    hold_until: Option<Instant>,
    guard: TimeoutGuard<A>,
    span: tracing::Span,
}

impl<A: Api> PendingHeader<A> {
    /// When the request next needs the tile: at the end of its hold or at its timeout.
    fn due(&self, timeout: Duration) -> Instant {
        let timeout = self.received + timeout;
        self.hold_until.map_or(timeout, |hold| hold.min(timeout))
    }
}

/// Serves the proposer API without the async runtime.
pub struct ProposerApiTile<A: Api> {
    server: ApiServer,
    requests: Vec<Inbound>,
    closed: Vec<Token>,
    api: Arc<ProposerApi<A>>,
    terminating: Arc<AtomicBool>,
    slot_events: Arc<SharedVector<SlotUpdate>>,
    /// The chain's head and the duty of the slot after it, as the housekeeper last
    /// announced them.
    head_slot: Slot,
    duty: Option<BuilderGetValidatorsResponseEntry>,
    headers: FxHashMap<u64, PendingHeader<A>>,
    /// The earliest moment a pending request is due; until then none is looked at.
    next_due: Option<Instant>,
    /// The requests due this turn, kept for its allocation.
    due: Vec<u64>,
    request_timeout: Duration,
    prune: Repeater,
    prune_due: bool,
    next_id: u64,
    bids_tx: Sender<(u64, GetHeaderResult)>,
    bids_rx: Receiver<(u64, GetHeaderResult)>,
    signed: SignedBidCache,
}

impl<A: Api> ProposerApiTile<A> {
    pub fn new(
        addrs: &[SocketAddr],
        config: &RouterConfig,
        api: Arc<ProposerApi<A>>,
        terminating: Arc<AtomicBool>,
        slot_events: Arc<SharedVector<SlotUpdate>>,
    ) -> Self {
        let served = [(Route::Status, "GET"), (Route::GetHeader, "GET")];
        // Unbounded, but it never holds more than one answer per pending request.
        let (bids_tx, bids_rx) = crossbeam_channel::unbounded();
        Self {
            server: ApiServer::new("proposer_api", addrs, config, &served),
            requests: Vec::new(),
            closed: Vec::new(),
            api,
            terminating,
            slot_events,
            head_slot: Slot::default(),
            duty: None,
            headers: FxHashMap::default(),
            next_due: None,
            due: Vec::new(),
            request_timeout: API_REQUEST_TIMEOUT.into(),
            prune: Repeater::every(Duration::from_secs(LIMITER_PRUNE_INTERVAL_SECS)),
            prune_due: false,
            next_id: 0,
            bids_tx,
            bids_rx,
            signed: SignedBidCache::default(),
        }
    }

    fn respond_error(&mut self, responder: Responder, error: ProposerApiError) {
        let status = error.status_code().as_u16();
        // A 204 carries no body, and no content-type either.
        if status == 204 {
            self.server.respond(responder, status, &[], &[]);
        } else {
            self.server.respond_text(responder, status, &error.to_string());
        }
    }

    fn on_slot_msg(&mut self, msg: SlotMsg) {
        let Some(update) = self.slot_events.get(msg.slot_update_id) else { return };
        self.head_slot = update.bid_slot.as_u64().saturating_sub(1).into();
        self.duty.clone_from(&update.registration_data);
    }

    fn on_get_header(&mut self, request: Inbound) {
        let Some(params) = parse_header_params(&request.params) else {
            self.server.respond_text(request.responder, 400, "Invalid URL");
            return;
        };
        let span = info_span!(
            "get_header",
            id = request.responder.request_id.to_str().unwrap_or_default(),
            slot = params.slot,
            parent_hash = ?params.parent_hash,
        );
        let _entered = span.enter();

        self.api.report_request(
            ProposerRequestKind::GetHeader,
            params.slot,
            params.pubkey,
            request.received_ns,
            extract_request_id(&request.headers),
            &request.headers,
        );

        let validated = match self.api.validate_header_request(
            self.head_slot,
            self.duty.as_ref(),
            &params,
            &request.headers,
            &self.terminating,
        ) {
            Ok(validated) => validated,
            Err(error) => return self.respond_error(request.responder, error),
        };

        let mut guard = self.api.timeout_guard(
            &params,
            &request.headers,
            validated.ip_addr,
            validated.sleep_time,
            validated.timeout_ms,
            validated.timeout_source,
            request.received_ns,
        );
        // With no hold there is no sleep to interrupt: a caller that hangs up before the
        // auctioneer is asked gave up on the fetch, as on `api_port`.
        guard.done_sleep = validated.sleep_time.is_none();
        if let Some(sleep_time) = validated.sleep_time {
            debug!(
                ?sleep_time,
                ms_into_slot = validated.ms_into_slot,
                slot = params.slot,
                pubkey = ?params.pubkey,
                "timing game sleep"
            );
        }

        let received = Instant::now();
        let hold_until = received + Duration::from(validated.sleep_time.unwrap_or_default());
        self.next_id += 1;
        let pending = PendingHeader {
            id: self.next_id,
            responder: request.responder,
            params,
            encoding: Encoding::from_accept(&request.headers),
            peer: request.peer,
            ip_addr: validated.ip_addr,
            is_mev_boost: validated.is_mev_boost,
            user_agent: validated.user_agent,
            trace: GetHeaderTrace {
                receive: request.received_ns,
                validation_complete: validated.validation_complete_ns,
                ..Default::default()
            },
            received,
            hold_until: Some(hold_until),
            guard,
            span: span.clone(),
        };
        let due = pending.due(self.request_timeout);
        self.next_due = Some(self.next_due.map_or(due, |next| next.min(due)));
        self.headers.insert(pending.id, pending);
    }

    /// Asks the auctioneer for the requests whose hold has ended and answers 408 to
    /// those that waited too long. Returns whether any request moved on.
    fn advance_headers(&mut self) -> bool {
        let now = Instant::now();
        if self.next_due.is_none_or(|due| now < due) {
            return false;
        }
        let timeout = self.request_timeout;
        let mut due = std::mem::take(&mut self.due);
        due.extend(self.headers.values().filter(|p| p.due(timeout) <= now).map(|p| p.id));
        // In the order they arrived.
        due.sort_unstable();
        for id in due.drain(..) {
            let Some(pending) = self.headers.get_mut(&id) else { continue };
            if now.saturating_sub(pending.received) >= timeout {
                let Some(pending) = self.headers.remove(&id) else { continue };
                let source_ip = pending.ip_addr.map(|ip| ip.to_string());
                let path = Route::GetHeader.path();
                count_request_timeout(source_ip.as_deref().unwrap_or("unknown"), &path);
                self.server.respond(pending.responder, 408, &[], &[]);
                continue;
            }

            pending.hold_until = None;
            pending.guard.done_sleep = true;
            let reply = Reply::Tile { request: pending.id, tx: self.bids_tx.clone() };
            let handle = &self.api.auctioneer_handle;
            let sent = pending
                .span
                .in_scope(|| handle.get_header_reply(pending.params, pending.is_mev_boost, reply));
            if sent.is_err() {
                let Some(mut pending) = self.headers.remove(&id) else { continue };
                let _entered = pending.span.enter();
                error!("failed to send get_header to auctioneer");
                pending.guard.timed_out = None;
                self.respond_error(pending.responder, ProposerApiError::InternalServerError);
            }
        }
        self.due = due;
        self.next_due = self.headers.values().map(|pending| pending.due(timeout)).min();
        true
    }

    /// Answers the requests the auctioneer has replied to.
    fn deliver_bids(&mut self) -> bool {
        let mut worked = false;
        for _ in 0..MAX_ANSWERS_PER_TURN {
            let Ok((id, result)) = self.bids_rx.try_recv() else { break };
            worked = true;
            // Gone if its caller disconnected or timed out meanwhile.
            let Some(mut pending) = self.headers.remove(&id) else { continue };
            let span = pending.span.clone();
            let _entered = span.enter();
            pending.guard.done_fetch = true;

            let bid = match result {
                Ok(bid) => bid,
                Err(error) => {
                    self.respond_error(pending.responder, error);
                    continue;
                }
            };
            let (signed_bid, fork) = self.api.serve_bid(
                bid,
                pending.params,
                pending.trace,
                pending.is_mev_boost,
                pending.user_agent,
                pending.ip_addr,
                pending.peer,
                Some(&mut self.signed),
            );
            match pending.encoding {
                Encoding::Json => match serde_json::to_vec(&signed_bid) {
                    Ok(body) => self.server.respond(pending.responder, 200, &[JSON], &body),
                    Err(error) => self.respond_error(pending.responder, error.into()),
                },
                Encoding::Ssz => {
                    let fork = fork.to_string();
                    let headers = [("content-type", HEADER_SSZ), (CONSENSUS_VERSION_HEADER, &fork)];
                    let body = signed_bid.data.as_ssz_bytes();
                    self.server.respond(pending.responder, 200, &headers, &body);
                }
            }
        }
        worked
    }
}

impl<A: Api> Tile<HelixSpine> for ProposerApiTile<A> {
    fn try_init(&mut self, _adapter: &mut SpineAdapter<HelixSpine>) -> bool {
        // What the housekeeper announced before this tile was listening.
        (self.head_slot, self.duty) = self.api.curr_slot_info.slot_info();
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<HelixSpine>) {
        adapter.consume(|msg: SlotMsg, _| self.on_slot_msg(msg));

        let mut requests = std::mem::take(&mut self.requests);
        let mut worked = self.server.poll(&mut requests, &mut self.closed);
        for request in requests.drain(..) {
            match request.route {
                Route::Status => {
                    let terminating = self.terminating.load(Ordering::Relaxed);
                    let status = if terminating { 503 } else { 200 };
                    self.server.respond(request.responder, status, &[], &[]);
                }
                Route::GetHeader => self.on_get_header(request),
                route => unreachable!("{route:?} is not served by this tile"),
            }
        }
        self.requests = requests;
        // After the requests: one that arrived with its connection's close is pending
        // by now, and must be dropped as abandoned rather than served to nobody.
        for token in self.closed.drain(..) {
            self.headers.retain(|_, pending| pending.responder.token != token);
        }

        // Answers first: one that is already here must not lose to the timeout sweep.
        worked |= self.deliver_bids();
        worked |= self.advance_headers();
        if worked {
            adapter.mark_work();
        }

        // The sweep stops the tile for as long as it takes, so it waits for a moment
        // with nobody held.
        self.prune_due |= self.prune.fired();
        if self.prune_due && self.headers.is_empty() {
            self.prune_due = false;
            self.server.prune_limiters();
        }
    }

    fn teardown(mut self, _adapter: &mut SpineAdapter<HelixSpine>) {
        // The callers still held are cut off by the shutdown: they did not give up, and
        // are not reported as if they had.
        for (_, pending) in self.headers.drain() {
            std::mem::forget(pending.guard);
        }
    }
}

fn parse_header_params(params: &str) -> Option<GetHeaderParams> {
    let mut segments = params.split('/');
    let slot = segments.next()?.parse().ok()?;
    let parent_hash = segments.next()?.parse().ok()?;
    let pubkey = segments.next()?.parse().ok()?;
    Some(GetHeaderParams { slot, parent_hash, pubkey })
}
