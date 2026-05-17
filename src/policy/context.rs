use std::{
    collections::HashSet,
    net::IpAddr,
    time::{Duration, SystemTime},
};

use ipnet::IpNet;

use crate::types::{ExemptionReason, OffenceIdentity, PeerContext, PeerObservationId};

#[derive(Clone)]
pub(super) struct PolicyContext {
    pub(super) new_peer_grace_period: Duration,
    pub(super) decay_window: Duration,
    pub(super) ignore_peer_progress_at_or_above: f64,
    pub(super) allowlisted_ips: HashSet<IpAddr>,
    pub(super) allowlisted_cidrs: Vec<IpNet>,
}

impl PolicyContext {
    pub(super) fn peer_observation_id(&self, peer: &PeerContext) -> PeerObservationId {
        PeerObservationId {
            torrent_hash: peer.torrent.hash.clone(),
            peer_ip: peer.peer.ip,
            peer_port: peer.peer.port,
        }
    }

    pub(super) fn offence_identity(&self, peer: &PeerContext) -> OffenceIdentity {
        OffenceIdentity {
            torrent_hash: peer.torrent.hash.clone(),
            peer_ip: peer.peer.ip,
        }
    }

    pub(super) fn classify_exemption(&self, peer: &PeerContext) -> Option<ExemptionReason> {
        if !peer.torrent.in_scope {
            return Some(ExemptionReason::TorrentExcluded);
        }

        if self.is_allowlisted(peer.peer.ip) {
            return Some(ExemptionReason::AllowlistedPeer);
        }

        if peer.peer.progress >= self.ignore_peer_progress_at_or_above {
            return Some(ExemptionReason::NearComplete {
                progress: peer.peer.progress,
                threshold: self.ignore_peer_progress_at_or_above,
            });
        }

        if self.is_within_grace_period(peer.first_seen_at, peer.observed_at) {
            return Some(ExemptionReason::NewPeerGracePeriod {
                age: peer
                    .observed_at
                    .duration_since(peer.first_seen_at)
                    .unwrap_or_default(),
                grace_period: self.new_peer_grace_period,
            });
        }

        if peer.has_active_ban {
            return Some(ExemptionReason::AlreadyBanned);
        }

        None
    }

    fn is_allowlisted(&self, ip: IpAddr) -> bool {
        self.allowlisted_ips.contains(&ip)
            || self.allowlisted_cidrs.iter().any(|cidr| cidr.contains(&ip))
    }

    fn is_within_grace_period(&self, first_seen_at: SystemTime, observed_at: SystemTime) -> bool {
        observed_at
            .duration_since(first_seen_at)
            .unwrap_or_default()
            < self.new_peer_grace_period
    }

    pub(super) fn can_carry_over_session(
        &self,
        previous_observation_id: &PeerObservationId,
        previous_offence_identity: &OffenceIdentity,
        previous_last_seen_at: SystemTime,
        observation_id: &PeerObservationId,
        offence_identity: &OffenceIdentity,
        peer: &PeerContext,
    ) -> bool {
        previous_observation_id != observation_id
            && previous_observation_id.torrent_hash == observation_id.torrent_hash
            && previous_offence_identity == offence_identity
            && peer.observed_at >= previous_last_seen_at
            && peer
                .observed_at
                .duration_since(previous_last_seen_at)
                .unwrap_or_default()
                <= self.decay_window
    }
}
