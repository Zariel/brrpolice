use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub struct ServiceState {
    live: AtomicBool,
    ready: AtomicBool,
    shutting_down: AtomicBool,
}

impl ServiceState {
    pub fn new() -> Self {
        Self {
            live: AtomicBool::new(true),
            ready: AtomicBool::new(false),
            shutting_down: AtomicBool::new(false),
        }
    }

    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Relaxed);
    }

    pub fn begin_shutdown(&self) {
        self.ready.store(false, Ordering::Relaxed);
        self.shutting_down.store(true, Ordering::Relaxed);
        self.live.store(false, Ordering::Relaxed);
    }

    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Relaxed)
    }
}
