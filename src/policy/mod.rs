#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::Result;
use ipnet::IpNet;

use crate::{
    config::{FiltersConfig, PolicyConfig, ReceiveIdlePolicyConfig, ScorePolicyConfig},
    metrics::AppMetrics,
    persistence::{EnforcementWriteResult, PendingBanIntentRecord, Persistence},
    types::{
        BanDecision, BanDisposition, ExemptionReason, OffenceHistory, OffenceIdentity, PeerContext,
        PeerEvaluation, PeerObservationId, PeerPolicyAssessment, PeerPolicyEvaluation,
        PeerPolicyInput, PeerPolicySessionState, PeerSessionState, PolicyDiagnostic,
        PolicyDiagnosticValue, PolicyEvaluation, PolicySessionSnapshot, TorrentPeer,
    },
};

mod cache;
mod context;
mod helpers;
mod receive_idle;
mod registry;
mod score;
mod traits;

pub use cache::PolicyCycleCache;
pub use receive_idle::RECEIVE_IDLE_POLICY_NAME;
pub use registry::PolicyRegistry;
pub use score::SCORE_POLICY_NAME;
pub use traits::{
    PeerPolicy, PeerPolicyReplay, PeerPolicyStorage, PolicyDataStore, PolicySessionPreloadKind,
    RuntimePolicy,
};

use context::PolicyContext;
use helpers::*;
use receive_idle::ReceiveIdlePolicy;
use score::ScorePolicy;

#[cfg(test)]
mod tests;
