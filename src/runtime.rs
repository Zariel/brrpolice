use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub struct ServiceState {
    live: AtomicBool,
    shutting_down: AtomicBool,
    database_ready: AtomicBool,
    qbittorrent_ready: AtomicBool,
    recovery_complete: AtomicBool,
    poll_loop_entered: AtomicBool,
    runtime_healthy: AtomicBool,
}

impl ServiceState {
    pub fn new() -> Self {
        Self {
            live: AtomicBool::new(true),
            shutting_down: AtomicBool::new(false),
            database_ready: AtomicBool::new(false),
            qbittorrent_ready: AtomicBool::new(false),
            recovery_complete: AtomicBool::new(false),
            poll_loop_entered: AtomicBool::new(false),
            runtime_healthy: AtomicBool::new(true),
        }
    }

    pub fn mark_database_ready(&self) {
        self.database_ready.store(true, Ordering::Relaxed);
    }

    pub fn mark_qbittorrent_ready(&self) {
        self.qbittorrent_ready.store(true, Ordering::Relaxed);
    }

    pub fn mark_recovery_complete(&self) {
        self.recovery_complete.store(true, Ordering::Relaxed);
    }

    pub fn mark_poll_loop_entered(&self) {
        self.poll_loop_entered.store(true, Ordering::Relaxed);
    }

    pub fn mark_runtime_healthy(&self) {
        self.runtime_healthy.store(true, Ordering::Relaxed);
    }

    pub fn mark_runtime_unhealthy(&self) {
        self.runtime_healthy.store(false, Ordering::Relaxed);
    }

    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        self.live.store(false, Ordering::Relaxed);
    }

    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    pub fn is_database_ready(&self) -> bool {
        self.database_ready.load(Ordering::Relaxed)
    }

    pub fn is_qbittorrent_ready(&self) -> bool {
        self.qbittorrent_ready.load(Ordering::Relaxed)
    }

    pub fn is_recovery_complete(&self) -> bool {
        self.recovery_complete.load(Ordering::Relaxed)
    }

    pub fn is_poll_loop_entered(&self) -> bool {
        self.poll_loop_entered.load(Ordering::Relaxed)
    }

    pub fn is_runtime_healthy(&self) -> bool {
        self.runtime_healthy.load(Ordering::Relaxed)
    }

    pub fn is_ready(&self) -> bool {
        self.is_live()
            && !self.is_shutting_down()
            && self.is_database_ready()
            && self.is_qbittorrent_ready()
            && self.is_recovery_complete()
            && self.is_poll_loop_entered()
            && self.is_runtime_healthy()
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::ServiceState;

    #[test]
    fn readiness_requires_all_startup_gates() {
        let state = ServiceState::new();
        assert!(!state.is_ready());

        state.mark_database_ready();
        assert!(!state.is_ready());

        state.mark_qbittorrent_ready();
        assert!(!state.is_ready());

        state.mark_recovery_complete();
        assert!(!state.is_ready());

        state.mark_poll_loop_entered();
        assert!(state.is_ready());
    }

    #[test]
    fn shutdown_clears_readiness() {
        let state = ServiceState::new();
        state.mark_database_ready();
        state.mark_qbittorrent_ready();
        state.mark_recovery_complete();
        state.mark_poll_loop_entered();
        assert!(state.is_ready());

        state.begin_shutdown();
        assert!(!state.is_live());
        assert!(!state.is_ready());
        assert!(state.is_shutting_down());
    }

    #[test]
    fn runtime_health_clears_readiness_until_recovered() {
        let state = ServiceState::new();
        state.mark_database_ready();
        state.mark_qbittorrent_ready();
        state.mark_recovery_complete();
        state.mark_poll_loop_entered();
        assert!(state.is_ready());

        state.mark_runtime_unhealthy();
        assert!(!state.is_ready());

        state.mark_runtime_healthy();
        assert!(state.is_ready());
    }
}
