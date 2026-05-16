use super::*;

#[derive(Default)]
pub struct PolicyCycleCache {
    sessions_by_observation: HashMap<(String, PeerObservationId), Box<dyn PolicySessionSnapshot>>,
    latest_sessions_by_torrent_ip:
        HashMap<(String, String, IpAddr), Box<dyn PolicySessionSnapshot>>,
    offence_histories: HashMap<(String, OffenceIdentity), OffenceHistory>,
    batch_load_count: usize,
}

impl PolicyCycleCache {
    pub async fn load(
        persistence: &Persistence,
        policies: &[Arc<dyn RuntimePolicy>],
        torrent_hashes: &[String],
    ) -> Result<Self> {
        let policy_names = policies
            .iter()
            .map(|policy| policy.name())
            .collect::<Vec<_>>();
        let mut cache = Self::default();

        let mut peer_policy_session_policies = HashMap::new();
        for policy in policies {
            match policy.session_preload_kind() {
                PolicySessionPreloadKind::LegacyScore => {
                    policy
                        .preload_legacy_sessions(persistence, torrent_hashes, &mut cache)
                        .await?;
                    cache.batch_load_count += 1;
                }
                PolicySessionPreloadKind::PeerPolicySessions => {
                    peer_policy_session_policies.insert(policy.name(), policy);
                }
            }
        }

        if !peer_policy_session_policies.is_empty() {
            let peer_policy_session_names = peer_policy_session_policies
                .keys()
                .copied()
                .collect::<Vec<_>>();
            let sessions = persistence
                .load_peer_policy_sessions_for_policy_torrents(
                    &peer_policy_session_names,
                    torrent_hashes,
                )
                .await?;
            cache.batch_load_count += 1;
            for session in sessions {
                if let Some(policy) = peer_policy_session_policies.get(session.policy_name.as_str())
                {
                    policy.cache_peer_policy_session(session, &mut cache)?;
                }
            }
        }

        let offence_histories = persistence
            .load_policy_offence_histories_for_policy_torrents(&policy_names, torrent_hashes)
            .await?;
        cache.batch_load_count += 1;

        for record in offence_histories {
            cache
                .offence_histories
                .insert((record.policy_name, record.identity), record.history);
        }

        Ok(cache)
    }

    #[cfg(test)]
    pub fn batch_load_count(&self) -> usize {
        self.batch_load_count
    }

    pub(super) fn insert_session_snapshot(
        &mut self,
        policy_name: &'static str,
        observation_id: PeerObservationId,
        last_seen_at: SystemTime,
        snapshot: Box<dyn PolicySessionSnapshot>,
    ) {
        self.sessions_by_observation.insert(
            (policy_name.to_string(), observation_id.clone()),
            snapshot.clone(),
        );
        self.latest_sessions_by_torrent_ip
            .entry((
                policy_name.to_string(),
                observation_id.torrent_hash,
                observation_id.peer_ip,
            ))
            .and_modify(|existing| {
                if last_seen_at > existing.last_seen_at() {
                    *existing = snapshot.clone();
                }
            })
            .or_insert(snapshot);
    }
}

#[async_trait::async_trait]
impl PolicyDataStore for PolicyCycleCache {
    async fn get_previous_session(
        &self,
        policy_name: &str,
        peer: &TorrentPeer,
        observed_at: SystemTime,
        decay_window: Duration,
    ) -> Result<Option<Box<dyn PolicySessionSnapshot>>> {
        let policy_name = policy_name.to_string();
        let existing = self
            .sessions_by_observation
            .get(&(policy_name.clone(), peer.observation_id.clone()))
            .cloned();
        let carryover = if existing.is_none() {
            self.latest_sessions_by_torrent_ip
                .get(&(
                    policy_name,
                    peer.observation_id.torrent_hash.clone(),
                    peer.observation_id.peer_ip,
                ))
                .filter(|session| {
                    session_carryover_allowed(session.last_seen_at(), observed_at, decay_window)
                })
                .cloned()
        } else {
            None
        };
        Ok(existing.or(carryover))
    }

    async fn load_policy_offence_history(
        &self,
        policy_name: &str,
        identity: &OffenceIdentity,
    ) -> Result<OffenceHistory> {
        Ok(self
            .offence_histories
            .get(&(policy_name.to_string(), identity.clone()))
            .cloned()
            .unwrap_or(OffenceHistory {
                offence_count: 0,
                last_ban_expires_at: None,
            }))
    }
}
