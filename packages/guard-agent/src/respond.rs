//! Responses the agent carries out: stop a process tree, quarantine/restore a file, isolate the
//! machine from the network (keeping only its connection to Securovix) and release it.
//!
//! Isolation saves the exact firewall state first and restores exactly that on release:
//!   Windows: `netsh advfirewall export` -> block everything except the Securovix server ->
//!            `netsh advfirewall import` on release.
//!   Linux:   a dedicated nftables table with drop policies (a drop in any base chain wins), so
//!            release is just deleting that table; nothing else is touched.
//!   macOS:   not supported yet (reported as a failed command, never a silent success).
use crate::util::{home, now_ms, run};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use sysinfo::{Pid, System};

/// Processes the agent refuses to stop: stopping them blue-screens or logs everyone out.
const PROTECTED: &[&str] = &[
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "securovix-guard.exe",
    "securovix-guard", "init", "systemd", "launchd", "kernel_task", "sshd", "explorer.exe",
];

pub fn protected(name: &str) -> bool {
    PROTECTED.contains(&name.to_lowercase().as_str())
}

/// Stops `pid` and everything it started (children first). Refuses system processes and,
/// when `expected_name` is given, a pid that now belongs to a different program (pid reuse).
pub fn kill_tree(pid: u32, expected_name: Option<&str>) -> Result<String, String> {
    let mut sys = System::new();
    sys.refresh_processes();
    let me = sysinfo::get_current_pid().map(|p| p.as_u32()).unwrap_or(0);
    let target = sys.process(Pid::from_u32(pid)).ok_or_else(|| format!("process {pid} is no longer running"))?;
    let name = target.name().to_string();
    if let Some(expected) = expected_name {
        if !expected.is_empty() && !name.eq_ignore_ascii_case(expected) {
            return Err(format!("process {pid} is now \"{name}\", not \"{expected}\"; not stopping it"));
        }
    }
    if pid <= 4 || pid == me || protected(&name) {
        return Err(format!("refusing to stop {name} ({pid}): it is part of the operating system or Guard itself"));
    }
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (p, proc_) in sys.processes() {
        if let Some(parent) = proc_.parent() {
            children.entry(parent.as_u32()).or_default().push(p.as_u32());
        }
    }
    let mut order = Vec::new();
    let mut stack = vec![pid];
    while let Some(p) = stack.pop() {
        if order.contains(&p) || order.len() > 512 {
            continue;
        }
        order.push(p);
        if let Some(kids) = children.get(&p) {
            stack.extend(kids.iter().copied());
        }
    }
    let mut stopped: usize = 0;
    for p in order.iter().rev() {
        if let Some(proc_) = sys.process(Pid::from_u32(*p)) {
            if *p != me && !protected(proc_.name()) && proc_.kill() {
                stopped += 1;
            }
        }
    }
    Ok(format!("Stopped {name} ({pid}) and {} process(es) it started.", stopped.saturating_sub(1)))
}

// ---------- quarantine ----------

#[derive(Serialize, Deserialize, Default)]
struct QuarantineIndex {
    items: HashMap<String, QuarantineItem>,
}

#[derive(Serialize, Deserialize, Clone)]
struct QuarantineItem {
    original: String,
    sha256: Option<String>,
    at: u64,
}

fn quarantine_dir() -> PathBuf {
    home().join("quarantine")
}

fn load_index() -> QuarantineIndex {
    std::fs::read(quarantine_dir().join("index.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_index(index: &QuarantineIndex) -> Result<(), String> {
    std::fs::write(quarantine_dir().join("index.json"), serde_json::to_vec_pretty(index).unwrap_or_default()).map_err(|e| e.to_string())
}

fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    std::fs::copy(from, to)?; // across volumes
    std::fs::remove_file(from)
}

/// Moves a file into the quarantine folder (readable by SYSTEM/root and administrators only) and
/// strips execute permission. Refuses if the file's hash is not the one the server named.
pub fn quarantine(path: &str, expected_sha: Option<&str>) -> Result<Value, String> {
    let source = PathBuf::from(path);
    if !source.is_file() {
        return Err(format!("{path} does not exist (already removed?)"));
    }
    let sha = crate::util::sha256_file(&source, 512 * 1024 * 1024);
    if let (Some(expected), Some(actual)) = (expected_sha, sha.as_deref()) {
        if !expected.is_empty() && !expected.eq_ignore_ascii_case(actual) {
            return Err("the file changed since it was reported (different SHA-256); not touching it".into());
        }
    }
    std::fs::create_dir_all(quarantine_dir()).map_err(|e| e.to_string())?;
    let id = format!("q{}", now_ms());
    let target = quarantine_dir().join(format!("{id}.quarantined"));
    move_file(&source, &target).map_err(|e| format!("could not move {path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000));
    }
    let mut index = load_index();
    index.items.insert(id.clone(), QuarantineItem { original: path.to_string(), sha256: sha.clone(), at: now_ms() });
    save_index(&index)?;
    Ok(json!({ "quarantineId": id, "original": path, "sha256": sha }))
}

pub fn restore(undo: &Value, fallback_path: Option<&str>) -> Result<String, String> {
    let mut index = load_index();
    let id = undo.get("quarantineId").and_then(|v| v.as_str()).map(String::from).or_else(|| {
        let wanted = fallback_path?;
        index.items.iter().find(|(_, item)| item.original == wanted).map(|(id, _)| id.clone())
    });
    let id = id.ok_or("nothing in quarantine for this file")?;
    let item = index.items.get(&id).cloned().ok_or("nothing in quarantine for this file")?;
    let stored = quarantine_dir().join(format!("{id}.quarantined"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o644));
    }
    if Path::new(&item.original).exists() {
        return Err(format!("{} exists again; not overwriting it", item.original));
    }
    move_file(&stored, Path::new(&item.original)).map_err(|e| e.to_string())?;
    index.items.remove(&id);
    save_index(&index)?;
    Ok(format!("Restored {}.", item.original))
}

// ---------- isolation ----------

/// The Securovix server's addresses and port, resolved before the network is closed.
pub fn server_endpoints(server: &str) -> Result<(Vec<IpAddr>, u16), String> {
    let without_scheme = server.split("://").nth(1).unwrap_or(server);
    let authority = without_scheme.split('/').next().unwrap_or("");
    let default_port = if server.starts_with("http://") { 80 } else { 443 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => (h.to_string(), p.parse().unwrap_or(default_port)),
        _ => (authority.trim_matches(|c| c == '[' || c == ']').to_string(), default_port),
    };
    let mut ips: Vec<IpAddr> = (host.as_str(), port).to_socket_addrs().map_err(|e| format!("cannot resolve {host}: {e}"))?.map(|a| a.ip()).collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return Err(format!("{host} resolved to no addresses"));
    }
    Ok((ips, port))
}

pub fn windows_isolation_plan(ips: &[IpAddr], port: u16, backup: &str) -> Vec<Vec<String>> {
    let list = ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",");
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    vec![
        s(&["advfirewall", "export", backup]),
        s(&["advfirewall", "firewall", "delete", "rule", "name=all"]),
        s(&["advfirewall", "set", "allprofiles", "state", "on"]),
        s(&["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"]),
        vec![
            "advfirewall".into(), "firewall".into(), "add".into(), "rule".into(), "name=SecurovixGuard-Isolation".into(), "dir=out".into(), "action=allow".into(),
            "protocol=TCP".into(), format!("remoteip={list}"), format!("remoteport={port}"),
        ],
    ]
}

pub fn windows_release_plan(backup: &str) -> Vec<Vec<String>> {
    vec![vec!["advfirewall".into(), "import".into(), backup.into()]]
}

#[cfg_attr(windows, allow(dead_code))]
pub fn linux_isolation_plan(ips: &[IpAddr], port: u16) -> Vec<Vec<String>> {
    let v4: Vec<String> = ips.iter().filter(|ip| ip.is_ipv4()).map(|ip| ip.to_string()).collect();
    let v6: Vec<String> = ips.iter().filter(|ip| ip.is_ipv6()).map(|ip| ip.to_string()).collect();
    let t = "securovix_guard";
    let mut plan: Vec<Vec<String>> = vec![
        vec!["add".into(), "table".into(), "inet".into(), t.into()],
        vec!["add".into(), "chain".into(), "inet".into(), t.into(), "input".into(), "{ type filter hook input priority -10 ; policy drop ; }".into()],
        vec!["add".into(), "chain".into(), "inet".into(), t.into(), "output".into(), "{ type filter hook output priority -10 ; policy drop ; }".into()],
        vec!["add".into(), "rule".into(), "inet".into(), t.into(), "input".into(), "iif".into(), "lo".into(), "accept".into()],
        vec!["add".into(), "rule".into(), "inet".into(), t.into(), "output".into(), "oif".into(), "lo".into(), "accept".into()],
    ];
    for (family, list) in [("ip", &v4), ("ip6", &v6)] {
        if list.is_empty() {
            continue;
        }
        let set = format!("{{ {} }}", list.join(", "));
        plan.push(vec!["add".into(), "rule".into(), "inet".into(), t.into(), "output".into(), family.into(), "daddr".into(), set.clone(), "tcp".into(), "dport".into(), port.to_string(), "accept".into()]);
        plan.push(vec!["add".into(), "rule".into(), "inet".into(), t.into(), "input".into(), family.into(), "saddr".into(), set, "tcp".into(), "sport".into(), port.to_string(), "ct".into(), "state".into(), "established".into(), "accept".into()]);
    }
    plan
}

fn run_plan(program: &str, plan: &[Vec<String>]) -> Result<(), String> {
    for step in plan {
        let args: Vec<&str> = step.iter().map(|s| s.as_str()).collect();
        let (ok, out) = run(program, &args);
        if !ok {
            return Err(format!("{program} {} failed: {}", args.join(" "), out.trim()));
        }
    }
    Ok(())
}

pub fn isolate(server: &str) -> Result<Value, String> {
    let (ips, port) = server_endpoints(server)?;
    let allowed: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
    #[cfg(windows)]
    {
        let backup = home().join("firewall-before-isolation.wfw");
        if backup.exists() {
            return Ok(json!({ "alreadyIsolated": true, "allowed": allowed }));
        }
        let backup_s = backup.to_string_lossy().to_string();
        let plan = windows_isolation_plan(&ips, port, &backup_s);
        if let Err(e) = run_plan("netsh", &plan) {
            if backup.exists() {
                let _ = run_plan("netsh", &windows_release_plan(&backup_s)); // put things back
                let _ = std::fs::remove_file(&backup);
            }
            return Err(e);
        }
        return Ok(json!({ "backup": backup_s, "allowed": allowed, "port": port }));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = run("nft", &["delete", "table", "inet", "securovix_guard"]);
        if let Err(e) = run_plan("nft", &linux_isolation_plan(&ips, port)) {
            let _ = run("nft", &["delete", "table", "inet", "securovix_guard"]);
            return Err(format!("{e} (isolation needs nftables)"));
        }
        return Ok(json!({ "table": "inet securovix_guard", "allowed": allowed, "port": port }));
    }
    #[allow(unreachable_code)]
    Err(format!("isolation is not supported on {} yet", std::env::consts::OS))
}

pub fn release(_undo: &Value) -> Result<String, String> {
    #[cfg(windows)]
    {
        let backup = _undo.get("backup").and_then(|v| v.as_str()).map(PathBuf::from).unwrap_or_else(|| home().join("firewall-before-isolation.wfw"));
        if !backup.exists() {
            return Err("no saved firewall configuration to restore; the machine may not be isolated".into());
        }
        run_plan("netsh", &windows_release_plan(&backup.to_string_lossy()))?;
        let _ = std::fs::remove_file(&backup);
        return Ok("Firewall restored to exactly how it was before isolation.".into());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let (ok, out) = run("nft", &["delete", "table", "inet", "securovix_guard"]);
        if !ok && !out.contains("No such file") {
            return Err(format!("nft delete table failed: {}", out.trim()));
        }
        return Ok("Isolation rules removed; the rest of the firewall was never changed.".into());
    }
    #[allow(unreachable_code)]
    Err(format!("isolation is not supported on {} yet", std::env::consts::OS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_plans_allow_only_the_server() {
        let ips: Vec<IpAddr> = vec!["203.0.113.10".parse().unwrap(), "2001:db8::10".parse().unwrap()];
        let win = windows_isolation_plan(&ips, 443, "C:\\g\\fw.wfw");
        assert_eq!(win[0], vec!["advfirewall", "export", "C:\\g\\fw.wfw"], "the backup is taken first");
        assert!(win.last().unwrap().contains(&"remoteip=203.0.113.10,2001:db8::10".to_string()));
        assert_eq!(windows_release_plan("C:\\g\\fw.wfw")[0][1], "import");
        let nft = linux_isolation_plan(&ips, 8443);
        let flat: Vec<String> = nft.iter().map(|s| s.join(" ")).collect();
        assert!(flat.iter().any(|l| l.contains("policy drop")));
        assert!(flat.iter().any(|l| l.contains("ip daddr { 203.0.113.10 } tcp dport 8443 accept")));
        assert!(flat.iter().any(|l| l.contains("ip6 daddr { 2001:db8::10 } tcp dport 8443 accept")));
    }

    #[test]
    fn server_url_parsing() {
        let (ips, port) = server_endpoints("http://127.0.0.1:3000/").unwrap();
        assert_eq!(port, 3000);
        assert_eq!(ips[0].to_string(), "127.0.0.1");
        assert_eq!(server_endpoints("https://127.0.0.1").unwrap().1, 443);
    }

    #[test]
    fn system_processes_are_protected() {
        assert!(protected("LSASS.EXE"));
        assert!(protected("systemd"));
        assert!(!protected("lock.exe"));
    }

    #[test]
    fn quarantine_and_restore_round_trip() {
        let dir = std::env::temp_dir().join(format!("sg-q-{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("SECUROVIX_GUARD_HOME", dir.join("home"));
        let file = dir.join("evil.exe");
        std::fs::write(&file, b"MZ not really").unwrap();
        let path = file.to_string_lossy().to_string();
        assert!(quarantine(&path, Some(&"0".repeat(64))).is_err(), "wrong hash: untouched");
        assert!(file.exists());
        let data = quarantine(&path, None).unwrap();
        assert!(!file.exists());
        assert!(restore(&data, None).unwrap().starts_with("Restored"));
        assert_eq!(std::fs::read(&file).unwrap(), b"MZ not really");
        let _ = std::fs::remove_dir_all(dir);
    }
}
