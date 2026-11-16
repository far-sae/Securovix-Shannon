//! File monitor: watches people's document folders, plants canary (decoy) files, feeds the local
//! ransomware detector, and stops the most likely culprit when the detector says so.
//!
//! The OS file-change APIs do not say which process changed a file, so the culprit is chosen as
//! the process that wrote the most bytes in the last moments (excluding system processes and
//! Guard). The server is told exactly what was stopped and why.
use crate::event::{Event, FileInfo, ProcessInfo};
use crate::ransomware::{looks_encrypted, Detector, Verdict};
use crate::shared::Shared;
use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind, RecursiveMode, Watcher};
use serde_json::json;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, System, UpdateKind};

pub const CANARY_NAMES: &[&str] = &["0000-securovix-canary.docx", "0000-securovix-canary.xlsx"];

fn canary_text() -> String {
    "Securovix Guard decoy file. Please leave it in place: Guard watches it to catch ransomware early.\n".repeat(20)
}

/// True when a decoy still holds exactly what Guard wrote. Backup tools, indexers and antivirus
/// scans touch a file's attributes and timestamps without changing a byte; that is not an attack.
pub fn canary_intact(path: &Path) -> bool {
    std::fs::read(path).map(|bytes| bytes == canary_text().as_bytes()).unwrap_or(false)
}

/// Document folders of every profile on the machine, plus the policy's extra folders.
pub fn watch_dirs(user_folders: bool, extra: &[String]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if user_folders {
        let roots: Vec<PathBuf> = if cfg!(windows) {
            vec![PathBuf::from(std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()) + "\\Users")]
        } else if cfg!(target_os = "macos") {
            vec![PathBuf::from("/Users")]
        } else {
            vec![PathBuf::from("/home"), PathBuf::from("/root")]
        };
        for root in roots {
            let profiles: Vec<PathBuf> = if root.ends_with("root") { vec![root.clone()] } else { std::fs::read_dir(&root).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default() };
            for profile in profiles {
                let name = profile.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
                if ["public", "default", "default user", "all users", "shared"].contains(&name.as_str()) {
                    continue;
                }
                for sub in ["Documents", "Desktop", "Downloads", "Pictures"] {
                    let dir = profile.join(sub);
                    if dir.is_dir() {
                        dirs.push(dir);
                    }
                }
            }
        }
    }
    dirs.extend(extra.iter().map(PathBuf::from).filter(|p| p.is_dir()));
    dirs.sort();
    dirs.dedup();
    dirs
}

/// Decoy files nobody has a reason to touch. Content is deliberately plain text in a document
/// name: any change at all, including encryption, is a signal.
pub fn plant_canaries(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut planted = Vec::new();
    for dir in dirs {
        for name in CANARY_NAMES {
            let path = dir.join(name);
            if !path.exists() {
                if std::fs::write(&path, canary_text()).is_err() {
                    continue;
                }
                #[cfg(windows)]
                {
                    let _ = crate::util::run("attrib", &["+h", &path.to_string_lossy()]);
                }
            }
            planted.push(path);
        }
    }
    planted
}

fn read_header(path: &Path, limit: usize) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; limit];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// File-change notifications do not say which process made the change, so the agent only stops
/// a process it can attribute with confidence: one that started in the last 30 minutes AND runs
/// from a folder ordinary users can write to (Downloads, Temp, AppData\Roaming, Public,
/// ProgramData, /tmp) - how ransomware droppers arrive. Installed applications never qualify, so a
/// busy editor or browser is never stopped by mistake. With no confident candidate the agent stops
/// nothing and the server recommends isolating the machine instead (which can be undone).
pub fn confident_suspect(run_secs: u64, exe: &str) -> bool {
    run_secs < 30 * 60 && crate::procmon::user_writable(exe)
}

fn suspect(sys: &mut System) -> Option<(u32, String, String)> {
    sys.refresh_processes_specifics(ProcessRefreshKind::new().with_disk_usage().with_exe(UpdateKind::OnlyIfNotSet));
    let me = sysinfo::get_current_pid().map(|p| p.as_u32()).unwrap_or(0);
    sys.processes()
        .iter()
        .filter(|(pid, p)| pid.as_u32() > 4 && pid.as_u32() != me && !crate::respond::protected(p.name()) && p.disk_usage().written_bytes > 0)
        .filter_map(|(pid, p)| {
            let exe = p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
            confident_suspect(p.run_time(), &exe).then(|| (p.disk_usage().written_bytes, pid.as_u32(), p.name().to_string(), exe))
        })
        .max_by_key(|(written, ..)| *written)
        .map(|(_, pid, name, exe)| (pid, name, exe))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decoy_that_was_only_touched_is_intact() {
        let dir = std::env::temp_dir().join(format!("svx-canary-test-{}", crate::util::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let planted = plant_canaries(std::slice::from_ref(&dir));
        assert_eq!(planted.len(), CANARY_NAMES.len());
        assert!(canary_intact(&planted[0]), "freshly planted");
        std::fs::write(&planted[0], b"\x13\x37 encrypted").unwrap();
        assert!(!canary_intact(&planted[0]), "rewritten");
        assert!(!canary_intact(&dir.join("gone.docx")), "missing counts as changed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_new_programs_from_user_writable_folders_can_be_stopped() {
        assert!(confident_suspect(30, "C:\\Users\\amy\\Downloads\\invoice.exe"));
        assert!(confident_suspect(600, "C:\\Users\\amy\\AppData\\Local\\Temp\\x\\viewer.exe"));
        assert!(!confident_suspect(30, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"), "installed app");
        assert!(!confident_suspect(30, "C:\\Users\\amy\\AppData\\Local\\Programs\\cursor\\Cursor.exe"), "per-user installed app");
        assert!(!confident_suspect(7_200, "C:\\Users\\amy\\Downloads\\old-tool.exe"), "running for hours");
    }
}

fn respond(shared: &Arc<Shared>, sys: &mut System, verdict: Verdict, kind: &str, file: FileInfo, change: &str) {
    let policy = shared.policy();
    let culprit = suspect(sys);
    let mut killed = false;
    let mut kill_detail = String::new();
    if verdict.kill && policy.ransomware.auto_kill {
        if let Some((pid, name, _)) = &culprit {
            match crate::respond::kill_tree(*pid, Some(name)) {
                Ok(d) => {
                    killed = true;
                    kill_detail = d;
                }
                Err(e) => kill_detail = e,
            }
        }
    }
    let mut event = Event::new(kind);
    event.file = Some(file);
    if let Some((pid, name, path)) = &culprit {
        event.process = Some(ProcessInfo { pid: *pid, name: name.clone(), path: Some(path.clone()).filter(|p| !p.is_empty()), ..Default::default() });
    }
    event.detail = Some(json!({
        "reason": verdict.reason,
        "files": verdict.files,
        "change": change,
        "pid": culprit.as_ref().map(|c| c.0),
        "process": culprit.as_ref().map(|c| c.1.clone()),
        "killed": killed,
        "killDetail": if culprit.is_none() && verdict.kill { "No process could be identified with confidence, so none was stopped. Isolate the machine.".to_string() } else { kill_detail },
    }));
    shared.emit_urgent(event);
}

pub fn run(shared: Arc<Shared>) {
    let policy = shared.policy();
    let mut dirs = watch_dirs(policy.watch_user_folders, &policy.extra_watch);
    if policy.canaries {
        let planted = plant_canaries(&dirs);
        shared.canaries.lock().unwrap().extend(planted);
    }
    let (tx, rx) = channel();
    let mut watcher = match notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    }) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("file monitor unavailable: {e}");
            return;
        }
    };
    let mut watching = 0;
    for dir in &dirs {
        if watcher.watch(dir, RecursiveMode::Recursive).is_ok() {
            watching += 1;
        }
    }
    *shared.watched.lock().unwrap() = watching;
    let home = crate::util::home();
    let mut detector = Detector::new(policy.ransomware.clone());
    let mut sys = System::new();
    sys.refresh_processes();
    let mut pending_from: Option<(PathBuf, u64)> = None;
    let mut last_checked: HashMap<PathBuf, u64> = HashMap::new();
    let mut last_policy = policy.version;

    while !shared.stopping() {
        let res = match rx.recv_timeout(Duration::from_millis(1000)) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => {
                sys.refresh_processes(); // keep per-process write counters current
                let p = shared.policy();
                if p.version != last_policy {
                    detector.set_policy(p.ransomware.clone());
                    last_policy = p.version;
                    // Folders added in the dashboard are watched from now on, without a restart.
                    // Folders removed there stay watched until the agent restarts: dropping
                    // protection is never the silent default.
                    for dir in watch_dirs(p.watch_user_folders, &p.extra_watch) {
                        if !dirs.contains(&dir) && watcher.watch(&dir, RecursiveMode::Recursive).is_ok() {
                            if p.canaries {
                                let planted = plant_canaries(std::slice::from_ref(&dir));
                                shared.canaries.lock().unwrap().extend(planted);
                            }
                            dirs.push(dir);
                            *shared.watched.lock().unwrap() += 1;
                        }
                    }
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let Ok(event) = res else { continue };
        let now = crate::util::now_ms();
        let canaries = shared.canaries.lock().unwrap().clone();
        let is_canary = |p: &Path| canaries.contains(p);
        let renames: Vec<(PathBuf, PathBuf)> = match &event.kind {
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)) if event.paths.len() >= 2 => vec![(event.paths[0].clone(), event.paths[1].clone())],
            EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
                pending_from = event.paths.first().map(|p| (p.clone(), now));
                vec![]
            }
            EventKind::Modify(ModifyKind::Name(RenameMode::To)) => match (pending_from.take(), event.paths.first()) {
                (Some((from, at)), Some(to)) if now.saturating_sub(at) < 2000 => vec![(from, to.clone())],
                _ => vec![],
            },
            _ => vec![],
        };
        for (from, to) in renames {
            if is_canary(&from) || is_canary(&to) {
                if let Some(v) = detector.on_canary(now, "renamed") {
                    respond(&shared, &mut sys, v, "canary.touched", FileInfo { path: from.to_string_lossy().into(), old_path: None, ..Default::default() }, "renamed");
                }
                continue;
            }
            if crate::ransomware::noisy(&to) {
                continue; // a tool's own folder (.git, node_modules, caches)
            }
            if crate::util::extension(&from) != crate::util::extension(&to) {
                // Ransomware writes then renames at once, so the write event's path is often gone
                // by the time it is read. Judge the content under its new name instead.
                if let Some(header) = read_header(&to, 64 * 1024).filter(|h| h.len() >= 512) {
                    let entropy = crate::util::entropy(&header);
                    if looks_encrypted(&to, &header, entropy, shared.policy().ransomware.high_entropy) {
                        last_checked.insert(to.clone(), now);
                        let mut e = Event::new("file.write");
                        e.file = Some(FileInfo { path: to.to_string_lossy().into(), entropy: Some((entropy * 100.0).round() / 100.0), ..Default::default() });
                        shared.emit(e);
                        if let Some(v) = detector.on_encrypted_write(now) {
                            respond(&shared, &mut sys, v, "ransomware.detected", FileInfo { path: to.to_string_lossy().into(), ..Default::default() }, "rewritten");
                        }
                    }
                }
                // Only renames that could be encryption are sent: a document given an unfamiliar
                // or an added extension. Downloads finishing and Office saving are not.
                if crate::ransomware::suspicious_rename(&from, &to) {
                    let mut e = Event::new("file.rename");
                    e.file = Some(FileInfo { path: to.to_string_lossy().into(), old_path: Some(from.to_string_lossy().into()), ..Default::default() });
                    shared.emit(e);
                }
                if let Some(v) = detector.on_rename(now, &from, &to) {
                    respond(&shared, &mut sys, v, "ransomware.detected", FileInfo { path: to.to_string_lossy().into(), old_path: Some(from.to_string_lossy().into()), ..Default::default() }, "renamed");
                }
            }
        }
        match &event.kind {
            EventKind::Remove(_) => {
                for p in &event.paths {
                    if is_canary(p) {
                        if let Some(v) = detector.on_canary(now, "deleted") {
                            respond(&shared, &mut sys, v, "canary.touched", FileInfo { path: p.to_string_lossy().into(), ..Default::default() }, "deleted");
                        }
                    }
                }
            }
            EventKind::Create(_) | EventKind::Modify(ModifyKind::Data(_)) | EventKind::Modify(ModifyKind::Any) => {
                for p in &event.paths {
                    if p.starts_with(&home) || !p.is_file() {
                        continue;
                    }
                    if is_canary(p) {
                        if canary_intact(p) {
                            continue; // only its attributes or timestamps were touched
                        }
                        if let Some(v) = detector.on_canary(now, "modified") {
                            respond(&shared, &mut sys, v, "canary.touched", FileInfo { path: p.to_string_lossy().into(), ..Default::default() }, "modified");
                        }
                        continue;
                    }
                    if crate::ransomware::noisy(p) {
                        continue;
                    }
                    if last_checked.get(p).is_some_and(|t| now.saturating_sub(*t) < 2000) {
                        continue;
                    }
                    last_checked.insert(p.clone(), now);
                    if last_checked.len() > 20_000 {
                        last_checked.clear();
                    }
                    let Some(header) = read_header(p, 64 * 1024) else { continue };
                    if header.len() < 512 {
                        continue;
                    }
                    let entropy = crate::util::entropy(&header);
                    let high = shared.policy().ransomware.high_entropy;
                    if looks_encrypted(p, &header, entropy, high) {
                        let mut e = Event::new("file.write");
                        e.file = Some(FileInfo { path: p.to_string_lossy().into(), entropy: Some((entropy * 100.0).round() / 100.0), ..Default::default() });
                        shared.emit(e);
                        if let Some(v) = detector.on_encrypted_write(now) {
                            respond(&shared, &mut sys, v, "ransomware.detected", FileInfo { path: p.to_string_lossy().into(), ..Default::default() }, "rewritten");
                        }
                    }
                }
            }
            _ => {}
        }
    }
    drop(watcher);
}
