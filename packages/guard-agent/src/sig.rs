//! SIGTERM and SIGINT on Unix: a flag the main loop reads, so the agent can say why it is going
//! quiet (the machine is shutting down, or someone stopped Guard) before it exits.
use std::sync::atomic::{AtomicBool, Ordering};

static TERMINATED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_signal: i32) {
    // Only an atomic store: the one thing that is always safe inside a signal handler.
    TERMINATED.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

pub fn install() {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    // SAFETY: `signal` is the C library's own function; the handler only stores to an atomic.
    unsafe {
        signal(SIGTERM, on_signal);
        signal(SIGINT, on_signal);
    }
}

pub fn terminated() -> bool {
    TERMINATED.load(Ordering::SeqCst)
}

/// True while the whole machine is shutting down or rebooting (systemd says "stopping").
pub fn system_stopping() -> bool {
    crate::util::run("systemctl", &["is-system-running"]).1.trim() == "stopping"
}
