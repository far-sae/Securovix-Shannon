//! Autostart watcher: reports new ways for a program to start by itself (Run keys, services,
//! scheduled tasks on Windows; cron, systemd units and autostart entries on Linux; launch agents
//! on macOS). Takes a snapshot every 30 seconds and reports what is new since the last one. The
//! first snapshot is the baseline and reports nothing.
use crate::event::{Event, Persistence};
use crate::shared::Shared;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

pub type Snapshot = BTreeMap<String, Persistence>;

/// Parses `reg query` output: "    Name    REG_SZ    value" lines.
pub fn parse_reg_values(output: &str, key: &str, kind: &str) -> Snapshot {
    let mut out = Snapshot::new();
    for line in output.lines() {
        let trimmed = line.trim_start();
        if !line.starts_with("    ") || trimmed.is_empty() {
            continue;
        }
        let Some(pos) = trimmed.find("    REG_") else { continue };
        let name = trimmed[..pos].trim().to_string();
        let rest = trimmed[pos + 4..].trim_start();
        let value = rest.split_once("    ").map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        out.insert(format!("{kind}|{key}|{name}"), Persistence { kind: kind.into(), name, command: value, path: None });
    }
    out
}

/// Parses `schtasks /query /fo csv /nh` output into task names.
pub fn parse_task_names(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|l| l.strip_prefix('"').and_then(|r| r.split_once('"')).map(|(name, _)| name.to_string()))
        .filter(|n| !n.is_empty() && n != "TaskName")
        .collect()
}

#[cfg(windows)]
fn snapshot() -> Snapshot {
    use crate::util::run;
    let mut snap = Snapshot::new();
    let mut run_keys = vec![
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
        "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
    ];
    let (_, users) = run("reg", &["query", "HKU"]);
    for line in users.lines().map(str::trim) {
        if line.starts_with("HKEY_USERS\\S-1-5-21") && !line.ends_with("_Classes") {
            run_keys.push(format!("{line}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
            run_keys.push(format!("{line}\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
        }
    }
    for key in run_keys {
        let (ok, out) = run("reg", &["query", &key]);
        if ok {
            snap.extend(parse_reg_values(&out, &key, "run-key"));
        }
    }
    let (ok, out) = run("reg", &["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services"]);
    if ok {
        for line in out.lines().map(str::trim) {
            if let Some(name) = line.strip_prefix("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\") {
                snap.insert(format!("service|{name}"), Persistence { kind: "service".into(), name: name.to_string(), command: String::new(), path: None });
            }
        }
    }
    let (ok, out) = run("schtasks", &["/query", "/fo", "csv", "/nh"]);
    if ok {
        for name in parse_task_names(&out) {
            snap.insert(format!("scheduled-task|{name}"), Persistence { kind: "scheduled-task".into(), name, command: String::new(), path: None });
        }
    }
    snap
}

/// Fills in the command for a new service or task (only looked up for new entries: cheap).
#[cfg(windows)]
fn describe(mut p: Persistence) -> Persistence {
    use crate::util::run;
    if p.kind == "service" {
        let key = format!("HKLM\\SYSTEM\\CurrentControlSet\\Services\\{}", p.name);
        let (_, out) = run("reg", &["query", &key, "/v", "ImagePath"]);
        if let Some(v) = parse_reg_values(&out, &key, "service").into_values().next() {
            p.command = v.command;
        }
    } else if p.kind == "scheduled-task" {
        let (_, out) = run("schtasks", &["/query", "/tn", &p.name, "/v", "/fo", "list"]);
        if let Some(line) = out.lines().find(|l| l.trim_start().starts_with("Task To Run:")) {
            p.command = line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        }
    }
    p
}

#[cfg(not(windows))]
fn snapshot() -> Snapshot {
    let mut snap = Snapshot::new();
    let mut dirs: Vec<(String, &str)> = if cfg!(target_os = "macos") {
        vec![("/Library/LaunchAgents".into(), "launch-agent"), ("/Library/LaunchDaemons".into(), "launch-agent")]
    } else {
        vec![
            ("/etc/cron.d".into(), "cron"),
            ("/etc/cron.hourly".into(), "cron"),
            ("/etc/cron.daily".into(), "cron"),
            ("/var/spool/cron/crontabs".into(), "cron"),
            ("/var/spool/cron".into(), "cron"),
            ("/etc/systemd/system".into(), "systemd"),
            ("/root/.config/autostart".into(), "run-key"),
        ]
    };
    for home in ["/home", "/Users"] {
        for entry in std::fs::read_dir(home).into_iter().flatten().flatten() {
            let p = entry.path();
            dirs.push((p.join(".config/autostart").to_string_lossy().into(), "run-key"));
            dirs.push((p.join("Library/LaunchAgents").to_string_lossy().into(), "launch-agent"));
        }
    }
    for (dir, kind) in dirs {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let modified = entry.metadata().ok().and_then(|m| m.modified().ok()).and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
            let p = path.to_string_lossy().to_string();
            snap.insert(format!("{kind}|{p}|{modified}"), Persistence { kind: kind.into(), name: entry.file_name().to_string_lossy().into(), command: String::new(), path: Some(p) });
        }
    }
    snap
}

#[cfg(not(windows))]
fn describe(mut p: Persistence) -> Persistence {
    if let Some(path) = &p.path {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("ExecStart=") || l.starts_with("Exec=") || (!l.is_empty() && !l.starts_with('#') && !l.contains('=')) || l.contains("<string>/"))
            .unwrap_or("");
        p.command = crate::util::truncate(line.trim_start_matches("ExecStart=").trim_start_matches("Exec="), 2048);
    }
    p
}

pub fn diff(before: &Snapshot, after: &Snapshot) -> Vec<Persistence> {
    after.iter().filter(|(k, _)| !before.contains_key(*k)).map(|(_, v)| v.clone()).collect()
}

pub fn run(shared: Arc<Shared>) {
    let mut baseline = snapshot();
    while !shared.stopping() {
        for _ in 0..30 {
            if shared.stopping() {
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        let current = snapshot();
        for entry in diff(&baseline, &current) {
            let mut event = Event::new("persistence.created");
            event.persistence = Some(describe(entry));
            shared.emit(event);
        }
        baseline = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reg_query_and_schtasks() {
        let out = "\r\nHKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n    SecurityHealth    REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe\r\n    Updater    REG_SZ    C:\\Users\\amy\\AppData\\Roaming\\upd.exe -silent\r\n";
        let snap = parse_reg_values(out, "HKLM\\Run", "run-key");
        assert_eq!(snap.len(), 2);
        let upd = snap.values().find(|p| p.name == "Updater").unwrap();
        assert_eq!(upd.command, "C:\\Users\\amy\\AppData\\Roaming\\upd.exe -silent");
        let tasks = parse_task_names("\"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\",\"N/A\",\"Ready\"\r\n\"\\Evil\",\"10/11/2026 10:00:00\",\"Ready\"\r\n");
        assert_eq!(tasks, vec!["\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "\\Evil"]);
    }

    #[test]
    fn diff_reports_only_new_entries() {
        let mut a = Snapshot::new();
        a.insert("run-key|k|A".into(), Persistence { kind: "run-key".into(), name: "A".into(), ..Default::default() });
        let mut b = a.clone();
        b.insert("run-key|k|B".into(), Persistence { kind: "run-key".into(), name: "B".into(), ..Default::default() });
        let new = diff(&a, &b);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].name, "B");
        assert!(diff(&b, &a).is_empty(), "removals are not new autostarts");
    }
}
