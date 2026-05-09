#![allow(dead_code)]

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use anyhow::Result;
use tokio::sync::mpsc;

use crate::policy_trace::PolicyTraceRecord;

pub const DEFAULT_TRACE_CLIENT_BUFFER: usize = 64;

#[derive(Debug)]
pub struct PolicyTracePublisher {
    enabled: AtomicBool,
    max_clients: usize,
    client_buffer: usize,
    next_client_id: AtomicU64,
    total_dropped: AtomicU64,
    clients: Mutex<Vec<TraceClient>>,
}

impl PolicyTracePublisher {
    pub fn disabled() -> Self {
        Self::new(false, 0, DEFAULT_TRACE_CLIENT_BUFFER)
    }

    pub fn new(enabled: bool, max_clients: usize, client_buffer: usize) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            max_clients,
            client_buffer: client_buffer.max(1),
            next_client_id: AtomicU64::new(1),
            total_dropped: AtomicU64::new(0),
            clients: Mutex::new(Vec::new()),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn active_client_count(&self) -> usize {
        let mut clients = self.clients.lock().expect("trace client lock poisoned");
        prune_closed_clients(&mut clients);
        clients.len()
    }

    pub fn total_dropped(&self) -> u64 {
        self.total_dropped.load(Ordering::Relaxed)
    }

    pub fn should_publish(&self) -> bool {
        self.is_enabled() && self.active_client_count() > 0
    }

    pub fn subscribe(&self) -> std::result::Result<PolicyTraceSubscription, SubscribeError> {
        self.subscribe_with_filter(TraceSubscriptionFilter::default())
    }

    pub fn subscribe_with_filter(
        &self,
        filter: TraceSubscriptionFilter,
    ) -> std::result::Result<PolicyTraceSubscription, SubscribeError> {
        if !self.is_enabled() {
            return Err(SubscribeError::Disabled);
        }

        let mut clients = self.clients.lock().expect("trace client lock poisoned");
        prune_closed_clients(&mut clients);
        if clients.len() >= self.max_clients {
            return Err(SubscribeError::ClientLimitReached {
                max_clients: self.max_clients,
            });
        }

        let (tx, rx) = mpsc::channel(self.client_buffer);
        let client_id = self.next_client_id.fetch_add(1, Ordering::Relaxed);
        clients.push(TraceClient {
            id: client_id,
            tx,
            dropped: 0,
            filter,
        });

        Ok(PolicyTraceSubscription {
            client_id,
            receiver: rx,
        })
    }

    pub fn publish(&self, record: &PolicyTraceRecord) -> Result<PublishOutcome> {
        if !self.is_enabled() {
            return Ok(PublishOutcome::SkippedDisabled);
        }

        {
            let mut clients = self.clients.lock().expect("trace client lock poisoned");
            prune_closed_clients(&mut clients);
            if clients.is_empty() {
                return Ok(PublishOutcome::SkippedNoClients);
            }
        }

        {
            let clients = self.clients.lock().expect("trace client lock poisoned");
            if !clients.iter().any(|client| client.filter.matches(record)) {
                return Ok(PublishOutcome::Published {
                    delivered: 0,
                    dropped: 0,
                });
            }
        }

        let payload = serde_json::to_string(record)?;
        Ok(self.publish_serialized(record, payload))
    }

    fn publish_serialized(&self, record: &PolicyTraceRecord, payload: String) -> PublishOutcome {
        let mut clients = self.clients.lock().expect("trace client lock poisoned");
        prune_closed_clients(&mut clients);
        if clients.is_empty() {
            return PublishOutcome::SkippedNoClients;
        }

        let mut delivered = 0;
        let mut dropped = 0;
        clients.retain_mut(|client| {
            if !client.filter.matches(record) {
                return true;
            }
            match client.tx.try_send(payload.clone()) {
                Ok(()) => {
                    delivered += 1;
                    true
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    client.dropped = client.dropped.saturating_add(1);
                    dropped += 1;
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });

        if dropped > 0 {
            self.total_dropped.fetch_add(dropped, Ordering::Relaxed);
        }

        PublishOutcome::Published { delivered, dropped }
    }

    pub fn take_dropped_for_client(&self, client_id: u64) -> Option<u64> {
        let mut clients = self.clients.lock().expect("trace client lock poisoned");
        prune_closed_clients(&mut clients);
        let client = clients.iter_mut().find(|client| client.id == client_id)?;
        let dropped = client.dropped;
        client.dropped = 0;
        Some(dropped)
    }
}

#[derive(Debug)]
struct TraceClient {
    id: u64,
    tx: mpsc::Sender<String>,
    dropped: u64,
    filter: TraceSubscriptionFilter,
}

#[derive(Debug, Clone)]
pub struct TraceSubscriptionFilter {
    pub peer_ip: Option<IpAddr>,
    pub torrent_hash: Option<String>,
    pub sample_rate: f64,
}

impl Default for TraceSubscriptionFilter {
    fn default() -> Self {
        Self {
            peer_ip: None,
            torrent_hash: None,
            sample_rate: 1.0,
        }
    }
}

impl TraceSubscriptionFilter {
    fn matches(&self, record: &PolicyTraceRecord) -> bool {
        if let Some(peer_ip) = self.peer_ip
            && record.peer.ip != Some(peer_ip)
        {
            return false;
        }
        if let Some(torrent_hash) = &self.torrent_hash
            && record.torrent.hash != *torrent_hash
        {
            return false;
        }
        if self.sample_rate >= 1.0 {
            return true;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }

        let mut hasher = DefaultHasher::new();
        record.policy_trace_id.hash(&mut hasher);
        record.torrent.hash.hash(&mut hasher);
        record.peer.port.hash(&mut hasher);
        let threshold = (self.sample_rate * u64::MAX as f64) as u64;
        hasher.finish() <= threshold
    }
}

#[derive(Debug)]
pub struct PolicyTraceSubscription {
    pub client_id: u64,
    pub receiver: mpsc::Receiver<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    SkippedDisabled,
    SkippedNoClients,
    Published { delivered: usize, dropped: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeError {
    Disabled,
    ClientLimitReached { max_clients: usize },
}

fn prune_closed_clients(clients: &mut Vec<TraceClient>) {
    clients.retain(|client| !client.tx.is_closed());
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, UNIX_EPOCH},
    };

    use crate::{
        config::PolicyConfig,
        policy_trace::{
            POLICY_TRACE_SCHEMA_VERSION, PolicyTraceRecord, PolicyTraceRecordType,
            TraceDecisionOutput, TraceGuardrailInputs, TraceOffenceHistory, TracePeer,
            TracePeerSessionState, TracePolicyInputs, TraceRateBand, TraceSimulatorHints,
            TraceTorrent, trace_timestamp,
        },
        types::{
            BanDisposition, OffenceIdentity, PeerEvaluation, PeerObservationId, PeerSessionState,
        },
    };

    use super::*;

    #[test]
    fn publish_skips_serialization_when_disabled_or_without_clients() {
        let publisher = PolicyTracePublisher::disabled();
        let record = sample_record();

        assert_eq!(
            publisher.publish(&record).unwrap(),
            PublishOutcome::SkippedDisabled
        );

        publisher.set_enabled(true);
        assert_eq!(
            publisher.publish(&record).unwrap(),
            PublishOutcome::SkippedNoClients
        );
    }

    #[tokio::test]
    async fn connected_client_receives_serialized_records() {
        let publisher = PolicyTracePublisher::new(true, 1, 4);
        let mut subscription = publisher.subscribe().unwrap();
        let record = sample_record();

        assert_eq!(
            publisher.publish(&record).unwrap(),
            PublishOutcome::Published {
                delivered: 1,
                dropped: 0
            }
        );

        let payload = subscription.receiver.recv().await.unwrap();
        let decoded: PolicyTraceRecord = serde_json::from_str(&payload).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn slow_client_drops_records_without_backpressure() {
        let publisher = PolicyTracePublisher::new(true, 1, 1);
        let subscription = publisher.subscribe().unwrap();
        let record = sample_record();

        assert_eq!(
            publisher.publish(&record).unwrap(),
            PublishOutcome::Published {
                delivered: 1,
                dropped: 0
            }
        );
        assert_eq!(
            publisher.publish(&record).unwrap(),
            PublishOutcome::Published {
                delivered: 0,
                dropped: 1
            }
        );

        assert_eq!(publisher.total_dropped(), 1);
        assert_eq!(
            publisher.take_dropped_for_client(subscription.client_id),
            Some(1)
        );
        assert_eq!(
            publisher.take_dropped_for_client(subscription.client_id),
            Some(0)
        );
    }

    #[test]
    fn subscription_limit_counts_only_open_clients() {
        let publisher = PolicyTracePublisher::new(true, 1, 1);
        let subscription = publisher.subscribe().unwrap();

        assert_eq!(
            publisher.subscribe().unwrap_err(),
            SubscribeError::ClientLimitReached { max_clients: 1 }
        );

        drop(subscription);

        assert!(publisher.subscribe().is_ok());
    }

    fn sample_record() -> PolicyTraceRecord {
        let observed_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let peer_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let session = PeerSessionState {
            observation_id: PeerObservationId {
                torrent_hash: "torrent".to_string(),
                peer_ip,
                peer_port: 51413,
            },
            offence_identity: OffenceIdentity {
                torrent_hash: "torrent".to_string(),
                peer_ip,
            },
            first_seen_at: observed_at - Duration::from_secs(60),
            last_seen_at: observed_at,
            baseline_progress: 0.1,
            latest_progress: 0.1,
            rolling_avg_up_rate_bps: 1024,
            observed_duration: Duration::from_secs(60),
            bad_duration: Duration::from_secs(30),
            ban_score: 0.5,
            ban_score_above_threshold_duration: Duration::ZERO,
            churn_reconnect_count: 0,
            churn_window_started_at: None,
            churn_amplifier: 0.0,
            sample_count: 1,
            last_torrent_seeder_count: 3,
            last_exemption_reason: None,
            bannable_since: None,
            last_ban_decision_at: None,
        };
        let evaluation = PeerEvaluation {
            session: session.clone(),
            progress_delta: 0.0,
            sample_duration: Duration::from_secs(60),
            sample_up_rate_bps: 1024,
            is_bad_sample: true,
            is_bannable: false,
            sample_score_risk: 0.8,
            effective_sample_score_risk: 0.8,
        };
        let policy = PolicyConfig::default();

        PolicyTraceRecord {
            record_type: PolicyTraceRecordType::PeerObservation,
            schema_version: POLICY_TRACE_SCHEMA_VERSION,
            observed_at: trace_timestamp(observed_at),
            service_version: "0.1.0-test".to_string(),
            policy_trace_id: "test-trace".to_string(),
            config_fingerprint: "fingerprint".to_string(),
            torrent: TraceTorrent {
                hash: "torrent".to_string(),
                name: Some("name".to_string()),
                tracker: None,
                total_size_bytes: None,
                category: None,
                tags: Vec::new(),
                total_seeders: 3,
                in_scope: true,
            },
            peer: TracePeer {
                ip: Some(peer_ip),
                port: 51413,
                progress: 0.1,
                up_rate_bps: 1024,
            },
            prior_session: None,
            evaluated_session: TracePeerSessionState::from(&session),
            policy_inputs: TracePolicyInputs::from(&policy),
            guardrail_inputs: TraceGuardrailInputs {
                exemption_reason: None,
                allowlisted_peer: false,
                active_ban: false,
                reban_cooldown_remaining_ms: None,
                offence_history: TraceOffenceHistory {
                    offence_count: 0,
                    last_ban_expires_at: None,
                },
            },
            decision_output: TraceDecisionOutput::from_evaluation_and_disposition(
                &evaluation,
                &BanDisposition::NotBannableYet {
                    observed_duration: Duration::from_secs(60),
                    required_observation: policy.score.min_observation_duration,
                    bad_duration: Duration::ZERO,
                    required_bad_duration: policy.score.sustain_duration,
                },
            ),
            simulator_hints: TraceSimulatorHints {
                peer_observation_identity: (&session.observation_id).into(),
                peer_behaviour_identity: (&session.offence_identity).into(),
                sample_duration_ms: 60_000,
                sample_up_rate_bps: 1024,
                current_rate_band: TraceRateBand::from_rate(1024, policy.score.target_rate_bps),
                band_at_ban: None,
            },
        }
    }
}
