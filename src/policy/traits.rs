use super::*;

#[async_trait::async_trait]
pub trait PolicyDataStore: Send + Sync {
    async fn get_previous_session(
        &self,
        policy_name: &str,
        peer: &TorrentPeer,
        observed_at: SystemTime,
        decay_window: Duration,
    ) -> Result<Option<Box<dyn PolicySessionSnapshot>>>;
    async fn load_policy_offence_history(
        &self,
        policy_name: &str,
        identity: &OffenceIdentity,
    ) -> Result<OffenceHistory>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySessionPreloadKind {
    LegacyScore,
    PeerPolicySessions,
}

#[async_trait::async_trait]
/// Pure peer assessment behavior implemented by each concrete policy.
///
/// `PeerPolicy` owns the policy-local decision algorithm and bounded metric labels, but it does not
/// define how orchestration preloads state, persists assessments, or replays pending intents.
pub trait PeerPolicy: Send + Sync {
    fn name(&self) -> &'static str;
    fn metric_label(&self) -> &'static str {
        self.name()
    }
    fn reason_metric_label(&self, reason_code: &str) -> &'static str;
    fn assess_peer(&self, input: PeerPolicyInput<'_>) -> Result<PeerPolicyAssessment>;
    fn record_policy_specific_metrics(
        &self,
        _metrics: &AppMetrics,
        _assessment: &PeerPolicyAssessment,
    ) {
    }
}

#[async_trait::async_trait]
/// Storage integration required by the control loop for each runtime policy.
pub trait PeerPolicyStorage: PeerPolicy + Send + Sync {
    fn session_preload_kind(&self) -> PolicySessionPreloadKind;
    async fn preload_legacy_sessions(
        &self,
        _persistence: &Persistence,
        _torrent_hashes: &[String],
        _cache: &mut PolicyCycleCache,
    ) -> Result<()> {
        Ok(())
    }
    fn cache_peer_policy_session(
        &self,
        _session: PeerPolicySessionState,
        _cache: &mut PolicyCycleCache,
    ) -> Result<()> {
        anyhow::bail!("{} does not use peer_policy_sessions", self.name())
    }
    async fn load_previous_session(
        &self,
        store: &dyn PolicyDataStore,
        peer: &TorrentPeer,
        observed_at: SystemTime,
        decay_window: Duration,
    ) -> Result<Option<Box<dyn PolicySessionSnapshot>>>;
    async fn load_offence_history(
        &self,
        store: &dyn PolicyDataStore,
        peer: &PeerContext,
    ) -> Result<OffenceHistory>;
    async fn persist_assessment(
        &self,
        persistence: &Persistence,
        assessment: &PeerPolicyAssessment,
    ) -> Result<()>;
    async fn record_enforcement(
        &self,
        persistence: &Persistence,
        assessment: &PeerPolicyAssessment,
        decision: &BanDecision,
        enforced_at: SystemTime,
    ) -> Result<EnforcementWriteResult>;
}

#[async_trait::async_trait]
/// Pending-intent replay integration required by the control loop for each runtime policy.
pub trait PeerPolicyReplay: PeerPolicy + Send + Sync {
    async fn record_replayed_intent(
        &self,
        persistence: &Persistence,
        intent: &PendingBanIntentRecord,
        decision: &BanDecision,
        recovered_at: SystemTime,
    ) -> Result<EnforcementWriteResult>;
    async fn validate_replay_intent(
        &self,
        _persistence: &Persistence,
        _intent: &PendingBanIntentRecord,
    ) -> Result<()> {
        Ok(())
    }
}

/// Orchestration-facing policy boundary executed by the control loop.
///
/// Runtime policies combine pure peer assessment with the storage and replay hooks needed to run a
/// complete poll cycle. Keeping this separate from `PeerPolicy` makes the narrow decision engine
/// distinct from the operational workflow the control loop drives.
pub trait RuntimePolicy: PeerPolicy + PeerPolicyStorage + PeerPolicyReplay {}

impl<T> RuntimePolicy for T where T: PeerPolicy + PeerPolicyStorage + PeerPolicyReplay {}
