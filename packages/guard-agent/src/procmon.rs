//! Process monitor: new processes with command line, parent chain and file hash; stops and
//! quarantines files on the known-malicious hash list; sends unknown programs started from
//! user-writable folders to the sandbox when the policy allows.
//!
//! Polls the process table every 2 seconds (portable). Very short-lived processes can be missed
//! by polling; on Windows, Sysmon (winlog.rs) fills that gap when it is installed, and this
//! monitor then stops emitting its own process events to avoid duplicates.
use crate::event::{Event, Parent, ProcessInfo};
use crate::shared::Shared;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind, Users};

const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SAMPLE_BYTES: u64 = 32 * 1024 * 1024;

/// Folders ordinary users can write to: programs started from here deserve a closer look.
pub fn user_writable(path: &str) -> bool {
    let p = path.to_lowercase().replace('\\', "/");
    ["/downloads/", "/appdata/local/temp/", "/appdata/roaming/", "/users/public/", "/windows/temp/", "/programdata/", "/desktop/", "/tmp/", "/dev/shm/", "/var/tmp/"]
        .iter()
        .any(|needle| p.contains(needle))
}

struct HashCache {
    entries: HashMap<(PathBuf, u64, u64), String>,
}

impl HashCache {
    fn get(&mut self, path: &Path) -> Option<String> {
        let meta = std::fs::metadata(path).ok()?;
        let modified = meta.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        let key = (path.to_path_buf(), meta.len(), modified);
        if let Some(h) = self.entries.get(&key) {
            return Some(h.clone());
        }
        let h = crate::util::sha256_file(path, MAX_HASH_BYTES)?;
        if self.entries.len() > 5000 {
            self.entries.clear();
        }
        self.entries.insert(key, h.clone());
        Some(h)
    }
}

pub fn run(shared: Arc<Shared>) {
    let mut sys = System::new();
    let mut users = Users::new_with_refreshed_list();
    let mut seen: HashSet<(u32, u64)> = HashSet::new();
    let mut cache = HashCache { entries: HashMap::new() };
    let me = sysinfo::get_current_pid().map(|p| p.as_u32()).unwrap_or(0);
    let mut first = true;
    let mut ticks: u64 = 0;
    while !shared.stopping() {
        // refresh_processes() does not load command lines or users in sysinfo 0.30: ask for them.
        sys.refresh_processes_specifics(
            ProcessRefreshKind::new()
                .with_exe(UpdateKind::OnlyIfNotSet)
                .with_cmd(UpdateKind::OnlyIfNotSet)
                .with_user(UpdateKind::OnlyIfNotSet),
        );
        ticks += 1;
        if ticks % 150 == 0 {
            users.refresh_list();
        }
        let current: HashSet<(u32, u64)> = sys.processes().iter().map(|(pid, p)| (pid.as_u32(), p.start_time())).collect();
        if !first {
            let hashes = shared.hashes.read().unwrap().clone();
            let policy = shared.policy();
            for (pid, proc_) in sys.processes() {
                let key = (pid.as_u32(), proc_.start_time());
                if seen.contains(&key) || key.0 == me {
                    continue;
                }
                let exe = proc_.exe().map(|p| p.to_path_buf());
                let sha = exe.as_deref().and_then(|p| cache.get(p));
                let path = exe.as_ref().map(|p| p.to_string_lossy().to_string());
                if sha.as_deref().is_some_and(|h| shared.allowed(h)) || path.as_deref().is_some_and(|p| shared.allowed(p)) {
                    continue;
                }
                let mut parents = Vec::new();
                let mut cursor = proc_.parent();
                while let Some(ppid) = cursor {
                    if parents.len() >= 6 {
                        break;
                    }
                    match sys.process(ppid) {
                        Some(parent) => {
                            parents.push(Parent { name: parent.name().to_string(), pid: ppid.as_u32() });
                            cursor = parent.parent();
                        }
                        None => break,
                    }
                }
                let info = ProcessInfo {
                    pid: pid.as_u32(),
                    ppid: proc_.parent().map(|p| p.as_u32()),
                    name: proc_.name().to_string(),
                    path: path.clone(),
                    cmdline: Some(crate::util::truncate(&proc_.cmd().join(" "), crate::util::MAX_CMDLINE)).filter(|c| !c.is_empty()),
                    user: proc_.user_id().and_then(|u| users.get_user_by_id(u)).map(|u| u.name().to_string()),
                    sha256: sha.clone(),
                    parents,
                };
                let known_bad = sha.as_deref().is_some_and(|h| hashes.contains(h));
                if known_bad && policy.quarantine_known_malware {
                    block_malware(&shared, &sys, *pid, info);
                    continue;
                }
                if policy.auto_submit_executables {
                    if let (Some(p), Some(h)) = (exe.as_ref(), sha.as_ref()) {
                        maybe_submit(&shared, p, h);
                    }
                }
                if known_bad || !shared.sysmon.load(Ordering::Relaxed) {
                    let mut event = Event::new("process.start");
                    event.process = Some(info);
                    shared.emit(event);
                }
            }
        }
        seen = current;
        first = false;
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn block_malware(shared: &Arc<Shared>, sys: &System, pid: Pid, info: ProcessInfo) {
    let name = sys.process(pid).map(|p| p.name().to_string()).unwrap_or_default();
    let killed = crate::respond::kill_tree(pid.as_u32(), Some(&name));
    let quarantined = info.path.as_deref().map(|p| crate::respond::quarantine(p, info.sha256.as_deref()));
    let mut event = Event::new("malware.blocked");
    event.file = info.path.clone().map(|path| crate::event::FileInfo { path, sha256: info.sha256.clone(), ..Default::default() });
    event.detail = Some(json!({
        "killed": killed.is_ok(),
        "quarantined": matches!(quarantined, Some(Ok(_))),
        "killDetail": killed.unwrap_or_else(|e| e),
        "quarantine": quarantined.map(|r| r.unwrap_or_else(|e| json!({ "error": e }))),
    }));
    event.process = Some(info);
    shared.emit_urgent(event);
}

fn maybe_submit(shared: &Arc<Shared>, path: &Path, sha: &str) {
    let p = path.to_string_lossy().to_string();
    if !user_writable(&p) || std::fs::metadata(path).map(|m| m.len() > MAX_SAMPLE_BYTES).unwrap_or(true) {
        return;
    }
    if !shared.submitted.lock().unwrap().insert(sha.to_string()) {
        return;
    }
    let shared = shared.clone();
    let path = path.to_path_buf();
    let sha = sha.to_string();
    std::thread::spawn(move || {
        let (server, token) = {
            let c = shared.config.read().unwrap();
            (c.server.clone(), c.token.clone())
        };
        if let Ok(bytes) = std::fs::read(&path) {
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let _ = crate::api::Client::new(&server, &token).upload_sample(&bytes, &name, &sha, None);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_writable_locations() {
        assert!(user_writable("C:\\Users\\amy\\Downloads\\invoice.exe"));
        assert!(user_writable("C:\\Users\\amy\\AppData\\Local\\Temp\\x.exe"));
        assert!(user_writable("/tmp/x"));
        assert!(!user_writable("C:\\Users\\amy\\AppData\\Local\\Programs\\cursor\\Cursor.exe"), "per-user installed apps are not droppers");
        assert!(!user_writable("C:\\Program Files\\App\\app.exe"));
        assert!(!user_writable("/usr/bin/ls"));
    }
}
