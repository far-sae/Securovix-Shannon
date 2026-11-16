//! The agent's main loop: start the monitors, check in, upload events, run commands.
use crate::api::{Client, Command};
use crate::event::Event;
use crate::shared::Shared;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};

const MAX_SAMPLE_BYTES: u64 = 32 * 1024 * 1024;

pub fn start_monitors(shared: &Arc<Shared>) -> Vec<std::thread::JoinHandle<()>> {
    let mut handles = Vec::new();
    for (name, f) in [
        ("procmon", crate::procmon::run as fn(Arc<Shared>)),
        ("filemon", crate::filemon::run as fn(Arc<Shared>)),
        ("persistence", crate::persistence::run as fn(Arc<Shared>)),
        ("winlog", crate::winlog::run as fn(Arc<Shared>)),
    ] {
        let s = shared.clone();
        if let Ok(h) = std::thread::Builder::new().name(name.into()).spawn(move || f(s)) {
            handles.push(h);
        }
    }
    handles
}

fn own_stats(sys: &mut System, shared: &Shared) -> Value {
    let me = sysinfo::get_current_pid().unwrap_or(Pid::from_u32(0));
    sys.refresh_process(me);
    let (cpu, mem) = sys.process(me).map(|p| (p.cpu_usage() / sys.cpus().len().max(1) as f32, p.memory() / (1024 * 1024))).unwrap_or((0.0, 0));
    json!({
        "cpuPercent": (cpu * 10.0).round() / 10.0,
        "memoryMb": mem,
        "queued": shared.queue.len(),
        "sysmon": shared.sysmon.load(Ordering::Relaxed),
        "watched": *shared.watched.lock().unwrap(),
    })
}

fn param<'a>(cmd: &'a Command, key: &str) -> Option<&'a Value> {
    cmd.params.get(key).filter(|v| !v.is_null())
}

/// Runs one command from the server. Returns (ok, detail, data).
pub fn execute(shared: &Arc<Shared>, client: &Client, cmd: &Command) -> (bool, String, Value) {
    let text = |k: &str| param(cmd, k).and_then(|v| v.as_str()).map(String::from);
    match cmd.kind.as_str() {
        "isolate-host" => {
            let server = shared.config.read().unwrap().server.clone();
            match crate::respond::isolate(&server) {
                Ok(data) => {
                    let mut c = shared.config.write().unwrap();
                    c.isolated = true;
                    let _ = c.save();
                    (true, format!("Isolated. Only {} is reachable.", data.get("allowed").map(|a| a.to_string()).unwrap_or_default()), data)
                }
                Err(e) => (false, e, Value::Null),
            }
        }
        "release-host" => match crate::respond::release(&cmd.undo_data) {
            Ok(detail) => {
                let mut c = shared.config.write().unwrap();
                c.isolated = false;
                let _ = c.save();
                (true, detail, Value::Null)
            }
            Err(e) => (false, e, Value::Null),
        },
        "kill-process" => {
            let pid = param(cmd, "pid").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).unwrap_or(0) as u32;
            match crate::respond::kill_tree(pid, text("processName").as_deref()) {
                Ok(d) => (true, d, Value::Null),
                Err(e) => (false, e, Value::Null),
            }
        }
        "quarantine-file" => match text("path") {
            Some(path) => match crate::respond::quarantine(&path, text("sha256").as_deref()) {
                Ok(data) => (true, format!("Moved {path} to quarantine."), data),
                Err(e) => (false, e, Value::Null),
            },
            None => (false, "no path given".into(), Value::Null),
        },
        "restore-file" => match crate::respond::restore(&cmd.undo_data, text("path").as_deref()) {
            Ok(d) => (true, d, Value::Null),
            Err(e) => (false, e, Value::Null),
        },
        "collect-file" => {
            let Some(path) = text("path") else { return (false, "no path given".into(), Value::Null) };
            let p = std::path::Path::new(&path);
            match std::fs::metadata(p) {
                Ok(m) if m.is_file() && m.len() <= MAX_SAMPLE_BYTES => {}
                Ok(m) if m.len() > MAX_SAMPLE_BYTES => return (false, "the file is larger than 32 MB".into(), Value::Null),
                _ => return (false, format!("{path} is not a readable file"), Value::Null),
            }
            match std::fs::read(p) {
                Ok(bytes) => {
                    let sha = crate::util::sha256_bytes(&bytes);
                    let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    match client.upload_sample(&bytes, &name, &sha, Some(&cmd.id)) {
                        Ok(v) => (true, format!("Sent {name} to the sandbox."), json!({ "sha256": sha, "sample": v.get("sample") })),
                        Err(e) => (false, e, Value::Null),
                    }
                }
                Err(e) => (false, e.to_string(), Value::Null),
            }
        }
        other => (false, format!("this agent does not know the command \"{other}\""), Value::Null),
    }
}

fn flush(shared: &Arc<Shared>, client: &Client) {
    loop {
        let batch = shared.queue.take(500);
        if batch.is_empty() {
            return;
        }
        if client.send_events(&batch).is_err() {
            shared.queue.restore(batch);
            return;
        }
    }
}

fn check_in(shared: &Arc<Shared>, client: &Client, sys: &mut System) {
    let (policy_version, hash_version, isolated) = {
        let c = shared.config.read().unwrap();
        (c.policy.version, c.hash_version, c.isolated)
    };
    let body = json!({ "version": env!("CARGO_PKG_VERSION"), "policyVersion": policy_version, "hashVersion": hash_version, "isolated": isolated, "startedAt": shared.started_at, "stats": own_stats(sys, shared) });
    let Ok(reply) = client.check_in(body) else { return };
    if reply.policy.is_some() || reply.hashes.is_some() {
        let mut c = shared.config.write().unwrap();
        if let Some(policy) = reply.policy {
            c.policy = policy;
        }
        if let Some(h) = reply.hashes {
            c.hash_version = h.version;
            c.hashes = h.list;
            *shared.hashes.write().unwrap() = c.hash_set();
        }
        let _ = c.save();
    }
    for cmd in reply.commands {
        let (ok, detail, data) = execute(shared, client, &cmd);
        let _ = client.send_result(&cmd.id, ok, &detail, data);
    }
}

/// Runs until `shared.stop` is set (service stop, Ctrl+C).
pub fn run(shared: Arc<Shared>) {
    let (server, token) = {
        let c = shared.config.read().unwrap();
        (c.server.clone(), c.token.clone())
    };
    let client = Client::new(&server, &token);
    let monitors = start_monitors(&shared);
    let mut sys = System::new();
    let mut last_checkin = Instant::now() - Duration::from_secs(3600);
    let mut last_flush = Instant::now();
    while !shared.stopping() {
        #[cfg(unix)]
        if crate::sig::terminated() {
            // systemd stops every service when the machine shuts down; otherwise someone stopped Guard.
            if crate::sig::system_stopping() {
                report_offline(&shared, "shutdown");
            } else {
                report_stop(&shared, "the Guard service was stopped on this machine");
            }
            shared.stop.store(true, Ordering::SeqCst);
            break;
        }
        let policy = shared.policy();
        let urgent = shared.urgent.swap(false, Ordering::SeqCst);
        if urgent || last_flush.elapsed() >= Duration::from_secs(policy.flush_seconds.max(1)) {
            flush(&shared, &client);
            last_flush = Instant::now();
        }
        if urgent || last_checkin.elapsed() >= Duration::from_secs(policy.poll_seconds.max(2)) {
            check_in(&shared, &client, &mut sys);
            last_checkin = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    flush(&shared, &client);
    for h in monitors {
        let _ = h.join();
    }
}

/// Sent before the agent stops on purpose, so the server can tell "someone stopped Guard" from
/// "the laptop went to sleep".
pub fn report_stop(shared: &Arc<Shared>, reason: &str) {
    let (server, token) = {
        let c = shared.config.read().unwrap();
        (c.server.clone(), c.token.clone())
    };
    let mut event = Event::new("agent.tamper");
    event.detail = Some(json!({ "reason": reason }));
    let _ = Client::quick(&server, &token).send_events(&[event]);
}

/// Sent just before the machine shuts down or goes to sleep ("shutdown", "sleep"), so the
/// silence that follows is shown as "offline" instead of raising an alert.
pub fn report_offline(shared: &Arc<Shared>, reason: &str) {
    let (server, token) = {
        let c = shared.config.read().unwrap();
        (c.server.clone(), c.token.clone())
    };
    let mut event = Event::new("agent.offline");
    event.detail = Some(json!({ "reason": reason }));
    let _ = Client::quick(&server, &token).send_events(&[event]);
}
