#![allow(dead_code)]

use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};

#[derive(Debug, Clone)]
pub struct TorrentSummary {
    pub hash: String,
    pub name: String,
    pub total_seeders: u32,
    pub category: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TorrentScope {
    pub hash: String,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub total_seeders: u32,
    pub in_scope: bool,
}

#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub ip: IpAddr,
    pub port: u16,
    pub progress: f64,
    pub up_rate_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerObservationId {
    pub torrent_hash: String,
    pub peer_ip: IpAddr,
    pub peer_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffenceIdentity {
    pub peer_ip: IpAddr,
}

#[derive(Debug, Clone)]
pub struct PeerContext {
    pub torrent: TorrentScope,
    pub peer: PeerSnapshot,
    pub first_seen_at: SystemTime,
    pub observed_at: SystemTime,
    pub has_active_ban: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerSessionState {
    pub observation_id: PeerObservationId,
    pub offence_identity: OffenceIdentity,
    pub first_seen_at: SystemTime,
    pub last_seen_at: SystemTime,
    pub baseline_progress: f64,
    pub latest_progress: f64,
    pub rolling_avg_up_rate_bps: u64,
    pub observed_duration: Duration,
    pub bad_duration: Duration,
    pub sample_count: u32,
    pub last_torrent_seeder_count: u32,
    pub last_exemption_reason: Option<ExemptionReason>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExemptionReason {
    TorrentExcluded,
    InsufficientSeeders {
        total_seeders: u32,
        required_seeders: u32,
    },
    AllowlistedPeer,
    NearComplete {
        progress: f64,
        threshold: f64,
    },
    NewPeerGracePeriod {
        age: Duration,
        grace_period: Duration,
    },
    AlreadyBanned,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerEvaluation {
    pub session: PeerSessionState,
    pub progress_delta: f64,
    pub sample_duration: Duration,
    pub sample_up_rate_bps: u64,
    pub is_bad_sample: bool,
    pub is_bannable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffenceHistory {
    pub offence_count: u32,
    pub last_ban_expires_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanDecision {
    pub peer_ip: IpAddr,
    pub peer_port: u16,
    pub offence_number: u32,
    pub ttl: Duration,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BanDisposition {
    Exempt(ExemptionReason),
    NotBannableYet {
        observed_duration: Duration,
        required_observation: Duration,
        bad_duration: Duration,
        required_bad_duration: Duration,
    },
    RebanCooldown {
        remaining: Duration,
    },
    Ban(BanDecision),
}
