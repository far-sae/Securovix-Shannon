//! Windows event logs: Sysmon (when installed) and the Security log.
//!   Sysmon 1  ProcessCreate  -> process.start (catches processes too short-lived to poll)
//!   Sysmon 10 ProcessAccess  -> lsass.access when the target is lsass.exe
//!   Security 4624 type 10    -> logon (rdp) for the lateral-movement rule
//! Read with `wevtutil qe` from the last record seen, so nothing is read twice.
use crate::event::{Event, Logon, Parent, ProcessInfo};
use crate::shared::Shared;
use serde_json::json;
use std::collections::HashMap;

pub struct Record {
    pub event_id: u32,
    pub record_id: u64,
    pub data: HashMap<String, String>,
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let j = s[i..].find(end)? + i;
    Some(&s[i..j])
}

/// Parses `wevtutil qe /f:xml` output (a run of <Event> elements) without an XML library.
pub fn parse_events(xml: &str) -> Vec<Record> {
    let mut out = Vec::new();
    for chunk in xml.split("<Event ").skip(1) {
        let event_id = between(chunk, "<EventID", "</EventID>").and_then(|v| v.rsplit('>').next()).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let record_id = between(chunk, "<EventRecordID>", "</EventRecordID>").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let mut data = HashMap::new();
        let mut rest = chunk;
        while let Some(pos) = rest.find("<Data Name=") {
            rest = &rest[pos + "<Data Name=".len()..];
            let quote = rest.chars().next().unwrap_or('\'');
            let Some(name_end) = rest[1..].find(quote) else { break };
            let name = rest[1..1 + name_end].to_string();
            rest = &rest[1 + name_end + 1..];
            if rest.starts_with("/>") {
                data.insert(name, String::new());
                continue;
            }
            let Some(gt) = rest.find('>') else { break };
            let Some(close) = rest[gt + 1..].find("</Data>") else { break };
            data.insert(name, unescape(&rest[gt + 1..gt + 1 + close]));
            rest = &rest[gt + 1 + close..];
        }
        out.push(Record { event_id, record_id, data });
    }
    out
}

fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

pub fn to_event(channel: &str, r: &Record) -> Option<Event> {
    let d = |k: &str| r.data.get(k).cloned().unwrap_or_default();
    let num = |k: &str| d(k).trim().parse::<u32>().ok();
    match (channel, r.event_id) {
        ("sysmon", 1) => {
            let mut e = Event::new("process.start");
            let image = d("Image");
            let sha = d("Hashes").split(',').find_map(|h| h.strip_prefix("SHA256=")).map(|h| h.to_lowercase());
            e.process = Some(ProcessInfo {
                pid: num("ProcessId").unwrap_or(0),
                ppid: num("ParentProcessId"),
                name: base_name(&image),
                path: Some(image),
                cmdline: Some(crate::util::truncate(&d("CommandLine"), 8192)),
                user: Some(d("User")).filter(|u| !u.is_empty()),
                sha256: sha,
                parents: vec![Parent { name: base_name(&d("ParentImage")), pid: num("ParentProcessId").unwrap_or(0) }],
            });
            Some(e)
        }
        ("sysmon", 10) if d("TargetImage").to_lowercase().ends_with("\\lsass.exe") => {
            let mut e = Event::new("lsass.access");
            let source = d("SourceImage");
            e.process = Some(ProcessInfo { pid: num("SourceProcessId").unwrap_or(0), name: base_name(&source), path: Some(source), ..Default::default() });
            e.detail = Some(json!({ "access": d("GrantedAccess") }));
            Some(e)
        }
        ("security", 4624) if d("LogonType") == "10" => {
            let mut e = Event::new("logon");
            e.logon = Some(Logon { kind: "rdp".into(), source: d("IpAddress"), user: format!("{}\\{}", d("TargetDomainName"), d("TargetUserName")) });
            Some(e)
        }
        _ => None,
    }
}

#[cfg(windows)]
pub fn run(shared: std::sync::Arc<Shared>) {
    use crate::util::run as sh;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    let sysmon_installed = || ["Sysmon64", "Sysmon"].iter().any(|s| sh("sc", &["query", s]).1.contains("RUNNING"));
    let latest = |log: &str| -> u64 {
        let (_, out) = sh("wevtutil", &["qe", log, "/c:1", "/rd:true", "/f:xml"]);
        parse_events(&out).first().map(|r| r.record_id).unwrap_or(0)
    };
    let logs = [("sysmon", "Microsoft-Windows-Sysmon/Operational", "*[System[(EventID=1 or EventID=10)"), ("security", "Security", "*[System[(EventID=4624)")];
    let mut cursors: HashMap<&str, u64> = HashMap::new();
    let mut checks = 0u64;
    while !shared.stopping() {
        if checks % 20 == 0 {
            let active = shared.policy().use_sysmon && sysmon_installed();
            shared.sysmon.store(active, Ordering::Relaxed);
        }
        checks += 1;
        for (channel, log, filter) in logs {
            if channel == "sysmon" && !shared.sysmon.load(Ordering::Relaxed) {
                continue;
            }
            let cursor = *cursors.entry(channel).or_insert_with(|| latest(log));
            let query = format!("/q:{filter} and EventRecordID>{cursor}]]");
            let (ok, out) = sh("wevtutil", &["qe", log, &query, "/f:xml", "/c:500", "/rd:false"]);
            if !ok {
                continue;
            }
            let mut max = cursor;
            for record in parse_events(&out) {
                max = max.max(record.record_id);
                if let Some(event) = to_event(channel, &record) {
                    shared.emit(event);
                }
            }
            cursors.insert(channel, max);
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

#[cfg(not(windows))]
pub fn run(_shared: std::sync::Arc<Shared>) {}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSMON: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID><EventRecordID>4521</EventRecordID></System><EventData><Data Name='ProcessId'>4100</Data><Data Name='Image'>C:\Windows\System32\cmd.exe</Data><Data Name='CommandLine'>cmd.exe /c vssadmin delete shadows /all &amp; echo &lt;done&gt;</Data><Data Name='User'>CORP\amy</Data><Data Name='Hashes'>MD5=AA,SHA256=ABCDEF</Data><Data Name='ParentProcessId'>4000</Data><Data Name='ParentImage'>C:\Users\amy\AppData\Local\Temp\lock.exe</Data></EventData></Event><Event xmlns='x'><System><EventID>10</EventID><EventRecordID>4522</EventRecordID></System><EventData><Data Name='SourceProcessId'>666</Data><Data Name='SourceImage'>C:\Temp\evil.exe</Data><Data Name='TargetImage'>C:\Windows\system32\lsass.exe</Data><Data Name='GrantedAccess'>0x1010</Data><Data Name='Empty'/></EventData></Event>"#;

    #[test]
    fn sysmon_process_and_lsass_access() {
        let records = parse_events(SYSMON);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record_id, 4521);
        let p = to_event("sysmon", &records[0]).unwrap().process.unwrap();
        assert_eq!(p.name, "cmd.exe");
        assert_eq!(p.cmdline.as_deref(), Some("cmd.exe /c vssadmin delete shadows /all & echo <done>"));
        assert_eq!(p.sha256.as_deref(), Some("abcdef"));
        assert_eq!(p.parents[0].name, "lock.exe");
        let l = to_event("sysmon", &records[1]).unwrap();
        assert_eq!(l.kind, "lsass.access");
        assert_eq!(l.process.unwrap().name, "evil.exe");
        assert_eq!(records[1].data.get("Empty").map(String::as_str), Some(""));
    }

    #[test]
    fn rdp_logons_only() {
        let xml = r#"<Event x='1'><System><EventID>4624</EventID><EventRecordID>9</EventRecordID></System><EventData><Data Name="LogonType">10</Data><Data Name="IpAddress">10.0.0.66</Data><Data Name="TargetUserName">admin</Data><Data Name="TargetDomainName">CORP</Data></EventData></Event><Event x='1'><System><EventID>4624</EventID><EventRecordID>10</EventRecordID></System><EventData><Data Name="LogonType">2</Data></EventData></Event>"#;
        let records = parse_events(xml);
        let rdp = to_event("security", &records[0]).unwrap().logon.unwrap();
        assert_eq!((rdp.kind.as_str(), rdp.source.as_str(), rdp.user.as_str()), ("rdp", "10.0.0.66", "CORP\\admin"));
        assert!(to_event("security", &records[1]).is_none(), "console logons are not reported");
    }
}
