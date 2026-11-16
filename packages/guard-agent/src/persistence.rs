//! Autostart watcher: reports new ways for a program to start by itself (Run keys, services,
//! scheduled tasks and Startup folders on Windows; cron, systemd units, shell profiles,
//! ld.so.preload and autostart entries on Linux; launch agents on macOS). Takes a snapshot every
//! 30 seconds and reports what is new since the last one. The first snapshot is the baseline and
//! reports nothing.
//!
//! A new entry is described before it is sent, so the server can tell ordinary software from
//! something worth a look: the command it runs, who signed the program (Windows), where a Store
//! app shortcut really points, and which package owns the file (Linux).
use crate::event::{Event, Persistence, Signer};
use crate::shared::Shared;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

pub type Snapshot = BTreeMap<String, Persistence>;

const EXEC_EXT: &[&str] = &["exe", "dll", "sys", "com", "scr", "pif", "cpl", "ocx", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "msi", "jar", "lnk"];

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
        out.insert(format!("{kind}|{key}|{name}"), Persistence { kind: kind.into(), name, command: value, ..Default::default() });
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

/// Replaces %NAME% with what `env` says it is; unknown names are left as written.
pub fn expand_env(text: &str, env: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 && end <= 40 && after[..end].chars().all(|c| c.is_ascii_alphanumeric() || "_()".contains(c)) => {
                match env(&after[..end]) {
                    Some(value) => out.push_str(&value),
                    None => {
                        out.push('%');
                        out.push_str(&after[..end]);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The program an autostart command starts: the quoted path, or everything up to the first
/// program or script extension (an unquoted path may contain spaces). Environment variables and
/// the kernel spellings of driver paths (\??\C:\..., \SystemRoot\..., system32\...) are resolved.
/// None for a bare name such as "notepad.exe", which Windows finds through PATH.
pub fn main_program(command: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let text = expand_env(command.trim(), env);
    let path = if let Some(rest) = text.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").to_string()
    } else {
        let lower = text.to_ascii_lowercase();
        let bytes = lower.as_bytes();
        let mut end = None;
        for i in 0..bytes.len() {
            if bytes[i] != b'.' {
                continue;
            }
            let mut k = i + 1;
            while k < bytes.len() && k - i <= 5 && bytes[k].is_ascii_alphanumeric() {
                k += 1;
            }
            let boundary = k == bytes.len() || matches!(bytes[k], b' ' | b'\t' | b',' | b'"');
            if boundary && EXEC_EXT.contains(&&lower[i + 1..k]) {
                end = Some(k);
                break;
            }
        }
        match end {
            Some(k) => text[..k].to_string(),
            None => text.split_whitespace().next().unwrap_or("").to_string(),
        }
    };
    let windir = env("SystemRoot").or_else(|| env("windir")).unwrap_or_else(|| "C:\\Windows".into());
    let lower = path.to_ascii_lowercase();
    let path = if lower.starts_with("\\??\\") || lower.starts_with("\\\\?\\") {
        path[4..].to_string()
    } else if lower.starts_with("\\systemroot\\") {
        format!("{windir}{}", &path[11..])
    } else if lower.starts_with("system32\\") || lower.starts_with("syswow64\\") {
        format!("{windir}\\{path}")
    } else {
        path
    };
    (path.contains('\\') || path.contains('/')).then_some(path)
}

/// Folders only administrators can write to. A program there needs no publisher check: the
/// server does not report autostart entries that point into them.
pub fn protected_location(path: &str) -> bool {
    let p = path.to_ascii_lowercase().replace('/', "\\");
    let rest = if p.len() > 2 && p.as_bytes()[1] == b':' { &p[2..] } else { return false };
    if rest.starts_with("\\windows\\temp\\") || rest.starts_with("\\windows\\tasks\\") {
        return false;
    }
    rest.starts_with("\\windows\\") || rest.starts_with("\\program files\\") || rest.starts_with("\\program files (x86)\\")
}

/// Reads the answer of the publisher check: "Valid|CN=Microsoft Corporation, O=...".
pub fn parse_signature(output: &str) -> Option<Signer> {
    let line = output.lines().map(str::trim).rfind(|l| l.contains('|'))?;
    let (status, subject) = line.split_once('|')?;
    let status = match status.trim() {
        "Valid" => "valid",
        "NotSigned" => "unsigned",
        "Missing" | "" => return None,
        _ => "invalid", // HashMismatch, NotTrusted, UnknownError: signed, but the signature does not hold
    };
    let name = subject.find("CN=").map(|i| &subject[i + 3..]).map(|rest| match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or("").to_string(),
        None => rest.split(',').next().unwrap_or("").trim().to_string(),
    });
    Some(Signer { status: status.into(), subject: name.filter(|n| !n.is_empty()).map(|n| crate::util::truncate(&n, 200)) })
}

/// Reads `fsutil reparsepoint query` output for a Store app shortcut (an "app execution alias")
/// and returns the program it really starts. None when the file is not such a shortcut.
pub fn parse_app_exec_link(output: &str) -> Option<String> {
    if !output.to_ascii_lowercase().contains("0x8000001b") {
        return None;
    }
    let mut bytes: Vec<u8> = Vec::new();
    for line in output.lines() {
        let mut words = line.split_whitespace();
        let Some(offset) = words.next() else { continue };
        if offset.len() != 5 || !offset.ends_with(':') || !offset[..4].chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        for word in words.take(16) {
            match (word.len(), u8::from_str_radix(word, 16)) {
                (2, Ok(b)) => bytes.push(b),
                _ => break,
            }
        }
    }
    if bytes.len() < 8 {
        return None;
    }
    let units: Vec<u16> = bytes[4..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units).split('\0').map(str::trim).find(|s| s.len() > 3 && s.as_bytes()[1] == b':' && s.to_ascii_lowercase().ends_with(".exe")).map(String::from)
}

/// The lines of an autostart file that say what runs: every job of a cron file, the Exec lines
/// of a systemd unit or desktop entry, the commands of a shell profile.
#[cfg_attr(windows, allow(dead_code))]
pub fn job_lines(kind: &str, text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let keep = match kind {
            "systemd" => ["ExecStart=", "ExecStartPre=", "ExecStartPost="].iter().find_map(|k| line.strip_prefix(k)).map(|v| v.trim_start_matches(['-', '@', '+', '!', ':']).to_string()),
            "run-key" => line.strip_prefix("Exec=").map(String::from),
            "launch-agent" => line.contains("<string>/").then(|| line.replace("<string>", "").replace("</string>", "")),
            // In a cron file "NAME=value" lines set the environment; everything else is a job.
            "cron" => {
                let first = line.split_whitespace().next().unwrap_or("");
                let assignment = first.contains('=') && first.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
                (!assignment).then(|| line.to_string())
            }
            _ => Some(line.to_string()),
        };
        if let Some(l) = keep.filter(|l| !l.is_empty()) {
            out.push(l);
        }
        if out.len() >= 40 {
            break;
        }
    }
    crate::util::truncate(&out.join("\n"), 4096)
}

#[cfg(windows)]
fn profiles() -> Vec<std::path::PathBuf> {
    let users = std::path::PathBuf::from(std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()) + "\\Users");
    std::fs::read_dir(users)
        .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect())
        .unwrap_or_default()
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
                snap.insert(format!("service|{name}"), Persistence { kind: "service".into(), name: name.to_string(), ..Default::default() });
            }
        }
    }
    let (ok, out) = run("schtasks", &["/query", "/fo", "csv", "/nh"]);
    if ok {
        for name in parse_task_names(&out) {
            snap.insert(format!("scheduled-task|{name}"), Persistence { kind: "scheduled-task".into(), name, ..Default::default() });
        }
    }
    // Startup folders: whatever is dropped here runs at sign-in, with no registry entry at all.
    let mut startup = vec![std::path::PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup")];
    startup.extend(profiles().into_iter().map(|p| p.join("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")));
    for dir in startup {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if !path.is_file() || name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let modified = entry.metadata().ok().and_then(|m| m.modified().ok()).and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
            let p = path.to_string_lossy().to_string();
            snap.insert(format!("startup-folder|{p}|{modified}"), Persistence { kind: "startup-folder".into(), name, path: Some(p), ..Default::default() });
        }
    }
    snap
}

/// Runs a short PowerShell snippet with the file handed over in an environment variable, so a
/// path can never be read as part of the script.
#[cfg(windows)]
fn powershell(script: &str, path: &str) -> String {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("SVX_PATH", path)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

#[cfg(windows)]
pub fn signature(path: &str) -> Option<Signer> {
    parse_signature(&powershell("$s = Get-AuthenticodeSignature -LiteralPath $env:SVX_PATH -ErrorAction SilentlyContinue; if ($s) { $s.Status.ToString() + '|' + $s.SignerCertificate.Subject } else { 'Missing|' }", path))
}

/// The program a command starts, as a file that exists. Per-user variables (%LOCALAPPDATA%,
/// %APPDATA%, %USERPROFILE%, %TEMP%) mean nothing to a service running as SYSTEM, so each
/// profile on the machine is tried in turn.
#[cfg(windows)]
pub fn locate_program(command: &str) -> Option<String> {
    let system = |name: &str| std::env::var(name).ok();
    let lower = command.to_ascii_lowercase();
    if ["%localappdata%", "%appdata%", "%userprofile%", "%temp%", "%tmp%"].iter().any(|v| lower.contains(v)) {
        for profile in profiles() {
            let home = profile.to_string_lossy().to_string();
            let per_user = |name: &str| match name.to_ascii_uppercase().as_str() {
                "LOCALAPPDATA" => Some(format!("{home}\\AppData\\Local")),
                "APPDATA" => Some(format!("{home}\\AppData\\Roaming")),
                "USERPROFILE" => Some(home.clone()),
                "TEMP" | "TMP" => Some(format!("{home}\\AppData\\Local\\Temp")),
                other => std::env::var(other).ok(),
            };
            if let Some(path) = main_program(command, &per_user).filter(|p| std::path::Path::new(p).is_file()) {
                return Some(path);
            }
        }
    }
    main_program(command, &system)
}

/// Fills in what a new entry runs and what is known about that program. Only looked up for new
/// entries, so the cost (a registry read, at most one PowerShell start) is paid rarely.
#[cfg(windows)]
pub fn describe(mut p: Persistence) -> Persistence {
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
    } else if p.kind == "startup-folder" {
        let file = p.path.take().unwrap_or_default();
        if file.to_ascii_lowercase().ends_with(".lnk") {
            // A shortcut: what matters is the program it points to. When that cannot be read the
            // entry is sent without a command, which the server does not report.
            let out = powershell("$l = (New-Object -ComObject WScript.Shell).CreateShortcut($env:SVX_PATH); $l.TargetPath + '|' + $l.Arguments", &file);
            if let Some((target, args)) = out.trim().split_once('|').filter(|(t, _)| !t.trim().is_empty()) {
                p.command = format!("\"{}\" {}", target.trim(), args.trim()).trim().to_string();
            }
        } else {
            p.command = format!("\"{file}\"");
        }
    }
    p.command = crate::util::truncate(&p.command, 4096);
    if let Some(program) = locate_program(&p.command) {
        if program.to_ascii_lowercase().contains("\\appdata\\local\\microsoft\\windowsapps\\") {
            let (_, out) = run("fsutil", &["reparsepoint", "query", &program]);
            p.resolved = parse_app_exec_link(&out);
        }
        if p.resolved.is_none() && !protected_location(&program) && std::path::Path::new(&program).is_file() {
            p.signer = signature(&program);
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
            ("/etc/cron.weekly".into(), "cron"),
            ("/etc/cron.monthly".into(), "cron"),
            ("/var/spool/cron/crontabs".into(), "cron"),
            ("/var/spool/cron".into(), "cron"),
            ("/etc/systemd/system".into(), "systemd"),
            ("/etc/profile.d".into(), "shell-profile"),
            ("/root/.config/autostart".into(), "run-key"),
            ("/root/.config/systemd/user".into(), "systemd"),
        ]
    };
    for home in ["/home", "/Users"] {
        for entry in std::fs::read_dir(home).into_iter().flatten().flatten() {
            let p = entry.path();
            dirs.push((p.join(".config/autostart").to_string_lossy().into(), "run-key"));
            dirs.push((p.join(".config/systemd/user").to_string_lossy().into(), "systemd"));
            dirs.push((p.join("Library/LaunchAgents").to_string_lossy().into(), "launch-agent"));
        }
    }
    let mut files: Vec<(std::path::PathBuf, &str)> = Vec::new();
    for (dir, kind) in dirs {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            files.push((entry.path(), kind));
        }
    }
    if cfg!(target_os = "linux") {
        files.push(("/etc/crontab".into(), "cron"));
        files.push(("/etc/ld.so.preload".into(), "ld-preload"));
    }
    for (path, kind) in files {
        if !path.is_file() {
            continue;
        }
        let modified = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok()).and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        let p = path.to_string_lossy().to_string();
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        snap.insert(format!("{kind}|{p}|{modified}"), Persistence { kind: kind.into(), name, path: Some(p), ..Default::default() });
    }
    snap
}

/// The package that installed a file, when the system's package manager knows it.
#[cfg(not(windows))]
fn package_owner(path: &str) -> Option<String> {
    use crate::util::run;
    let (ok, out) = run("dpkg", &["-S", path]);
    if ok {
        return out.lines().next().and_then(|l| l.split_once(':')).map(|(pkg, _)| pkg.trim().to_string()).filter(|pkg| !pkg.is_empty() && !pkg.contains(' '));
    }
    let (ok, out) = run("rpm", &["-qf", "--queryformat", "%{NAME}", path]);
    (ok && !out.contains("not owned")).then(|| out.trim().to_string()).filter(|pkg| !pkg.is_empty() && !pkg.contains(' '))
}

#[cfg(not(windows))]
pub fn describe(mut p: Persistence) -> Persistence {
    if let Some(path) = &p.path {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        p.command = job_lines(&p.kind, &text);
        p.package_owner = package_owner(path);
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

    fn env(name: &str) -> Option<String> {
        match name.to_ascii_uppercase().as_str() {
            "WINDIR" | "SYSTEMROOT" => Some("C:\\Windows".into()),
            "PROGRAMFILES" => Some("C:\\Program Files".into()),
            "LOCALAPPDATA" => Some("C:\\Users\\amy\\AppData\\Local".into()),
            _ => None,
        }
    }

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

    #[test]
    fn finds_the_program_an_autostart_command_starts() {
        let of = |c: &str| main_program(c, &env);
        assert_eq!(of("\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window").as_deref(), Some("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"));
        assert_eq!(of("C:\\Program Files\\McAfee\\wps\\1.40.161.1\\dad\\mc-dad.exe /run now").as_deref(), Some("C:\\Program Files\\McAfee\\wps\\1.40.161.1\\dad\\mc-dad.exe"), "unquoted, spaces and dots in folders");
        assert_eq!(of("%windir%\\system32\\SecurityHealthSystray.exe").as_deref(), Some("C:\\Windows\\system32\\SecurityHealthSystray.exe"));
        assert_eq!(of("%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe /reporting").as_deref(), Some("C:\\Users\\amy\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe"));
        assert_eq!(of("\\??\\C:\\Program Files\\McAfee\\vpn\\SplitTunnelingDriver.sys").as_deref(), Some("C:\\Program Files\\McAfee\\vpn\\SplitTunnelingDriver.sys"));
        assert_eq!(of("\\SystemRoot\\System32\\drivers\\mfehidk.sys").as_deref(), Some("C:\\Windows\\System32\\drivers\\mfehidk.sys"));
        assert_eq!(of("system32\\DRIVERS\\nvlddmkm.sys").as_deref(), Some("C:\\Windows\\system32\\DRIVERS\\nvlddmkm.sys"));
        assert_eq!(of("C:\\Windows\\system32\\svchost.exe -k netsvcs -p").as_deref(), Some("C:\\Windows\\system32\\svchost.exe"));
        assert_eq!(of("wscript.exe \"C:\\Users\\amy\\AppData\\Roaming\\a.vbs\""), None, "a bare name is found through PATH");
        assert_eq!(of("%unknownvar%\\x.exe").as_deref(), Some("%unknownvar%\\x.exe"), "unknown variables are left as written");
        assert_eq!(of(""), None);
        assert_eq!(expand_env("100% sure %windir% %", &env), "100% sure C:\\Windows %");
    }

    #[test]
    fn protected_folders_need_no_publisher_check() {
        assert!(protected_location("C:\\Program Files\\App\\a.exe"));
        assert!(protected_location("c:\\windows\\system32\\svchost.exe"));
        assert!(protected_location("C:/Program Files (x86)/App/a.exe"));
        assert!(!protected_location("C:\\Windows\\Temp\\a.exe"));
        assert!(!protected_location("C:\\Users\\amy\\AppData\\Roaming\\a.exe"));
        assert!(!protected_location("C:\\ProgramData\\a.exe"));
        assert!(!protected_location("a.exe"));
    }

    #[test]
    fn reads_the_publisher_check() {
        let ms = parse_signature("Valid|CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US\r\n").unwrap();
        assert_eq!((ms.status.as_str(), ms.subject.as_deref()), ("valid", Some("Microsoft Corporation")));
        let quoted = parse_signature("Valid|CN=\"Discord, Inc.\", O=\"Discord, Inc.\"").unwrap();
        assert_eq!(quoted.subject.as_deref(), Some("Discord, Inc."));
        let unsigned = parse_signature("NotSigned|\r\n").unwrap();
        assert_eq!((unsigned.status.as_str(), unsigned.subject), ("unsigned", None));
        assert_eq!(parse_signature("HashMismatch|CN=Someone").unwrap().status, "invalid", "tampered after signing");
        assert!(parse_signature("Missing|").is_none(), "no file: nothing is known");
        assert!(parse_signature("").is_none());
        assert!(parse_signature("powershell is not recognized").is_none());
    }

    #[test]
    fn resolves_a_store_app_shortcut() {
        // `fsutil reparsepoint query` on a real app execution alias (Windows 11).
        let out = "Reparse Tag Value : 0x8000001b\r\nTag value: Microsoft\r\n\r\nReparse Data Length: 0x5c\r\nReparse Data:\r\n\
0000:  03 00 00 00 50 00 6b 00  67 00 5f 00 31 00 00 00  ....P.k.g._.1...\r\n\
0010:  50 00 6b 00 67 00 5f 00  31 00 21 00 41 00 00 00  P.k.g._.1.!.A...\r\n\
0020:  43 00 3a 00 5c 00 50 00  72 00 6f 00 67 00 72 00  C.:.\\.P.r.o.g.r.\r\n\
0030:  61 00 6d 00 20 00 46 00  69 00 6c 00 65 00 73 00  a.m. .F.i.l.e.s.\r\n\
0040:  5c 00 57 00 41 00 5c 00  61 00 2e 00 65 00 78 00  \\.W.A.\\.a...e.x.\r\n\
0050:  65 00 00 00 30 00 00 00                           e...0...\r\n";
        assert_eq!(parse_app_exec_link(out).as_deref(), Some("C:\\Program Files\\WA\\a.exe"));
        assert!(parse_app_exec_link("Reparse Tag Value : 0xa000000c\r\n0000:  00 00").is_none(), "an ordinary symbolic link");
        assert!(parse_app_exec_link("Error:  The file or directory is not a reparse point.").is_none());
    }

    #[test]
    fn reads_every_job_of_an_autostart_file() {
        let cron = "# backups\nSHELL=/bin/sh\nPATH=/usr/sbin:/usr/bin\n\n0 3 * * * root /usr/local/bin/backup.sh\n*/10 * * * * root /var/tmp/.cache/upd\n";
        assert_eq!(job_lines("cron", cron), "0 3 * * * root /usr/local/bin/backup.sh\n*/10 * * * * root /var/tmp/.cache/upd", "a job added below the first one is not missed");
        let unit = "[Unit]\nDescription=x\n[Service]\nExecStartPre=-/usr/bin/mkdir -p /run/x\nExecStart=/usr/local/bin/securovix-guard run\nRestart=always\n";
        assert_eq!(job_lines("systemd", unit), "/usr/bin/mkdir -p /run/x\n/usr/local/bin/securovix-guard run");
        assert_eq!(job_lines("run-key", "[Desktop Entry]\nName=x\nExec=/usr/bin/app --tray\n"), "/usr/bin/app --tray");
        assert_eq!(job_lines("ld-preload", "# none\n/usr/local/lib/libx.so\n"), "/usr/local/lib/libx.so");
        assert_eq!(job_lines("cron", "# only comments\n"), "");
    }
}
