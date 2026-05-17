use super::*;

#[derive(Clone)]
/// Builds runtime policy instances from policy config and shared filter context.
pub struct PolicyRegistry {
    config: PolicyConfig,
    allowlisted_ips: HashSet<IpAddr>,
    allowlisted_cidrs: Vec<IpNet>,
}

impl PolicyRegistry {
    pub fn new(mut config: PolicyConfig, filters: &FiltersConfig) -> Self {
        config.apply_legacy_score_aliases();
        let allowlisted_ips = filters
            .allowlist_peer_ips
            .iter()
            .filter_map(|value| value.parse::<IpAddr>().ok())
            .collect();
        let allowlisted_cidrs = filters
            .allowlist_peer_cidrs
            .iter()
            .filter_map(|value| value.parse::<IpNet>().ok())
            .collect();

        Self {
            config,
            allowlisted_ips,
            allowlisted_cidrs,
        }
    }

    fn context(&self) -> PolicyContext {
        PolicyContext {
            new_peer_grace_period: self.config.new_peer_grace_period,
            decay_window: self.config.decay_window,
            ignore_peer_progress_at_or_above: self.config.ignore_peer_progress_at_or_above,
            allowlisted_ips: self.allowlisted_ips.clone(),
            allowlisted_cidrs: self.allowlisted_cidrs.clone(),
        }
    }

    pub(super) fn score_policy(&self) -> ScorePolicy {
        ScorePolicy {
            context: self.context(),
            config: self.config.score.clone(),
        }
    }

    pub(super) fn receive_idle_policy(&self) -> ReceiveIdlePolicy {
        ReceiveIdlePolicy {
            context: self.context(),
            config: self.config.receive_idle.clone(),
        }
    }

    pub fn peer_observation_id(&self, peer: &PeerContext) -> PeerObservationId {
        self.context().peer_observation_id(peer)
    }

    pub fn enabled_peer_policies(&self) -> Vec<Arc<dyn RuntimePolicy>> {
        let mut policies: Vec<Arc<dyn RuntimePolicy>> = Vec::new();
        if self.config.score.enabled {
            policies.push(Arc::new(self.score_policy()));
        }
        if self.config.receive_idle.enabled {
            policies.push(Arc::new(self.receive_idle_policy()));
        }
        policies
    }

    pub fn replay_peer_policies(&self) -> Vec<Arc<dyn RuntimePolicy>> {
        vec![
            Arc::new(self.score_policy()),
            Arc::new(self.receive_idle_policy()),
        ]
    }

    pub fn offence_identity(&self, peer: &PeerContext) -> OffenceIdentity {
        self.context().offence_identity(peer)
    }

    pub fn classify_exemption(&self, peer: &PeerContext) -> Option<ExemptionReason> {
        self.context().classify_exemption(peer)
    }

    pub fn ban_ttl_for_offence(&self, offence_number: u32) -> Duration {
        self.score_policy().ban_ttl_for_offence(offence_number)
    }

    pub fn begin_session(
        &self,
        peer: &PeerContext,
        carryover: Option<&PeerSessionState>,
    ) -> PeerSessionState {
        self.score_policy().begin_session(peer, carryover)
    }

    pub fn evaluate_peer(
        &self,
        peer: &PeerContext,
        existing: Option<&PeerSessionState>,
    ) -> PeerEvaluation {
        self.score_policy().evaluate_peer(peer, existing)
    }

    pub fn decide_ban(
        &self,
        peer: &PeerContext,
        evaluation: &PeerEvaluation,
        history: &OffenceHistory,
    ) -> BanDisposition {
        self.score_policy().decide_ban(peer, evaluation, history)
    }

    pub fn record_ban_decision(
        &self,
        session: &PeerSessionState,
        decided_at: SystemTime,
    ) -> PeerSessionState {
        self.score_policy().record_ban_decision(session, decided_at)
    }

    pub fn begin_receive_idle_session(
        &self,
        peer: &PeerContext,
        carryover: Option<&PeerPolicySessionState>,
    ) -> PeerPolicySessionState {
        self.receive_idle_policy()
            .begin_receive_idle_session(peer, carryover)
    }

    pub fn evaluate_receive_idle_peer(
        &self,
        peer: &PeerContext,
        existing: Option<&PeerPolicySessionState>,
    ) -> PeerPolicyEvaluation {
        self.receive_idle_policy()
            .evaluate_receive_idle_peer(peer, existing)
    }

    pub fn decide_receive_idle_ban(
        &self,
        peer: &PeerContext,
        evaluation: &PeerPolicyEvaluation,
        history: &OffenceHistory,
    ) -> BanDisposition {
        self.receive_idle_policy()
            .decide_receive_idle_ban(peer, evaluation, history)
    }

    pub(super) fn required_progress_delta(
        &self,
        observed_duration: Duration,
        up_rate_bps: u64,
    ) -> f64 {
        self.score_policy()
            .required_progress_delta(observed_duration, up_rate_bps)
    }

    pub fn evaluate(&self) -> Vec<BanDecision> {
        Vec::new()
    }
}
