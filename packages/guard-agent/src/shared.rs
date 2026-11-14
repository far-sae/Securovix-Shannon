//! State shared by the agent's threads.
use crate::config::Config;
use crate::event::{Event, Queue};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};

pub struct Shared {
    pub queue: Queue,
    pub config: RwLock<Config>,
    pub hashes: RwLock<HashSet<String>>,
    pub stop: AtomicBool,
    /// Set when something urgent was queued (ransomware): the main loop flushes at once.
    pub urgent: AtomicBool,
    pub sysmon: AtomicBool,
    pub canaries: Mutex<HashSet<std::path::PathBuf>>,
    pub watched: Mutex<usize>,
    pub submitted: Mutex<HashSet<String>>,
}

impl Shared {
    pub fn new(config: Config) -> Shared {
        let hashes = config.hash_set();
        Shared {
            queue: Queue::new(20_000),
            config: RwLock::new(config),
            hashes: RwLock::new(hashes),
            stop: AtomicBool::new(false),
            urgent: AtomicBool::new(false),
            sysmon: AtomicBool::new(false),
            canaries: Mutex::new(HashSet::new()),
            watched: Mutex::new(0),
            submitted: Mutex::new(HashSet::new()),
        }
    }

    pub fn emit(&self, event: Event) {
        self.queue.push(event);
    }

    pub fn emit_urgent(&self, event: Event) {
        self.queue.push(event);
        self.urgent.store(true, Ordering::SeqCst);
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn policy(&self) -> crate::config::Policy {
        self.config.read().unwrap().policy.clone()
    }

    pub fn allowed(&self, value: &str) -> bool {
        let v = value.to_lowercase();
        self.config.read().unwrap().policy.allow.iter().any(|a| a == &v)
    }
}
