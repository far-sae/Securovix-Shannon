//! Local ransomware detector. Runs on the machine so it can stop encryption in seconds, without
//! waiting for the server. Signals:
//!   * a canary (decoy) file is changed, renamed or deleted -> act at once
//!   * many files renamed to the same new extension in a short window
//!   * many files rewritten with encrypted-looking content (high entropy, or a document whose
//!     header no longer matches its type)
//! Only canary hits and rename bursts backed by encrypted-looking writes stop a process; a burst
//! of high-entropy writes alone is reported but not acted on (backup and sync tools do that too).
use crate::config::RansomwarePolicy;
use std::collections::{HashMap, VecDeque};
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub reason: String,
    pub files: usize,
    pub kill: bool,
}

pub struct Detector {
    policy: RansomwarePolicy,
    renames: VecDeque<(u64, String)>,
    writes: VecDeque<u64>,
    quiet_until: HashMap<&'static str, u64>,
}

/// Extensions whose content is compressed by design: entropy says nothing, the header does.
const COMPRESSED: &[&str] = &[
    "zip", "7z", "rar", "gz", "bz2", "xz", "zst", "cab", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods", "pdf", "png", "jpg", "jpeg", "gif",
    "webp", "heic", "mp3", "mp4", "m4a", "mov", "avi", "mkv", "webm", "iso", "msi", "exe", "dll",
];

/// True when a file of a known type no longer starts with that type's signature: the classic
/// mark of a file encrypted in place without changing its name.
pub fn header_mismatch(ext: &str, header: &[u8]) -> bool {
    if header.len() < 4 {
        return false;
    }
    let expected: &[&[u8]] = match ext {
        "docx" | "xlsx" | "pptx" | "zip" | "odt" | "ods" | "jar" | "apk" => &[b"PK\x03\x04", b"PK\x05\x06"],
        "pdf" => &[b"%PDF"],
        "png" => &[b"\x89PNG"],
        "jpg" | "jpeg" => &[b"\xFF\xD8\xFF"],
        "gif" => &[b"GIF8"],
        "doc" | "xls" | "ppt" | "msg" => &[b"\xD0\xCF\x11\xE0"],
        _ => return false,
    };
    !expected.iter().any(|sig| header.starts_with(sig))
}

/// Whether a write looks like encryption. Plain documents get an entropy test; compressed types
/// get a header test (their entropy is always high).
pub fn looks_encrypted(path: &Path, header: &[u8], entropy: f64, high: f64) -> bool {
    let ext = crate::util::extension(path);
    if header_mismatch(&ext, header) {
        return entropy >= 7.0;
    }
    if COMPRESSED.contains(&ext.as_str()) {
        return false;
    }
    entropy >= high
}

impl Detector {
    pub fn new(policy: RansomwarePolicy) -> Self {
        Detector { policy, renames: VecDeque::new(), writes: VecDeque::new(), quiet_until: HashMap::new() }
    }

    pub fn set_policy(&mut self, policy: RansomwarePolicy) {
        self.policy = policy;
    }

    fn window(&self) -> u64 {
        self.policy.window_seconds.max(5) * 1000
    }

    fn trim(&mut self, now: u64) {
        let window = self.window();
        while self.renames.front().is_some_and(|(t, _)| *t + window < now) {
            self.renames.pop_front();
        }
        while self.writes.front().is_some_and(|t| *t + window < now) {
            self.writes.pop_front();
        }
    }

    fn quiet(&mut self, key: &'static str, now: u64) -> bool {
        if self.quiet_until.get(key).is_some_and(|until| *until > now) {
            return true;
        }
        self.quiet_until.insert(key, now + 30_000);
        false
    }

    pub fn on_canary(&mut self, now: u64, change: &str) -> Option<Verdict> {
        if self.quiet("canary", now) {
            return None;
        }
        Some(Verdict { reason: format!("a decoy (canary) file was {change}"), files: 1, kill: true })
    }

    pub fn on_rename(&mut self, now: u64, old: &Path, new: &Path) -> Option<Verdict> {
        let ext = crate::util::extension(new);
        if ext.is_empty() || ext == crate::util::extension(old) || ext.len() > 12 {
            return None;
        }
        self.trim(now);
        self.renames.push_back((now, ext.clone()));
        let same = self.renames.iter().filter(|(_, e)| *e == ext).count();
        if same < self.policy.rename_burst.max(5) || self.quiet("rename", now) {
            return None;
        }
        // Renaming alone can be a batch tool; renaming plus encrypted-looking writes is not.
        let kill = self.writes.len() >= 5 || same >= self.policy.rename_burst * 2;
        Some(Verdict { reason: format!("{same} files renamed to \".{ext}\" within {} seconds", self.policy.window_seconds), files: same, kill })
    }

    pub fn on_encrypted_write(&mut self, now: u64) -> Option<Verdict> {
        self.trim(now);
        self.writes.push_back(now);
        let count = self.writes.len();
        if count < self.policy.entropy_burst.max(5) || self.quiet("entropy", now) {
            return None;
        }
        Some(Verdict { reason: format!("{count} files rewritten with encrypted-looking content within {} seconds", self.policy.window_seconds), files: count, kill: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn detector() -> Detector {
        Detector::new(RansomwarePolicy::default())
    }

    #[test]
    fn canary_acts_at_once_then_stays_quiet_briefly() {
        let mut d = detector();
        let v = d.on_canary(1_000, "renamed").unwrap();
        assert!(v.kill);
        assert!(d.on_canary(2_000, "deleted").is_none());
        assert!(d.on_canary(40_000, "deleted").is_some());
    }

    #[test]
    fn rename_burst_with_encrypted_writes_stops_the_process() {
        let mut d = detector();
        for i in 0..6 {
            d.on_encrypted_write(1_000 + i);
        }
        let mut verdict = None;
        for i in 0..20 {
            let old = PathBuf::from(format!("C:/d/f{i}.docx"));
            let new = PathBuf::from(format!("C:/d/f{i}.docx.locked"));
            verdict = verdict.or(d.on_rename(2_000 + i * 100, &old, &new));
        }
        let v = verdict.expect("20 renames to .locked");
        assert!(v.kill);
        assert_eq!(v.files, 20);
    }

    #[test]
    fn a_batch_rename_alone_is_reported_not_killed() {
        let mut d = detector();
        let mut verdict = None;
        for i in 0..20 {
            verdict = verdict.or(d.on_rename(1_000 + i, Path::new(&format!("img{i}.jpeg")), Path::new(&format!("img{i}.jpg"))));
        }
        let v = verdict.unwrap();
        assert!(!v.kill);
    }

    #[test]
    fn same_extension_and_slow_renames_do_not_fire() {
        let mut d = detector();
        for i in 0..40 {
            assert!(d.on_rename(i * 10, Path::new("a.txt"), Path::new("b.txt")).is_none());
        }
        let mut d = detector();
        for i in 0..40u64 {
            assert!(d.on_rename(i * 60_000, Path::new(&format!("{i}.doc")), Path::new(&format!("{i}.enc"))).is_none());
        }
    }

    #[test]
    fn encrypted_looking_writes() {
        assert!(header_mismatch("docx", b"\x13\x37\xbe\xef rest"));
        assert!(!header_mismatch("docx", b"PK\x03\x04rest"));
        assert!(!header_mismatch("txt", b"anything"));
        assert!(looks_encrypted(Path::new("a.docx"), b"\x13\x37\xbe\xefxxxx", 7.9, 7.5), "a docx that is no longer a zip");
        assert!(!looks_encrypted(Path::new("a.docx"), b"PK\x03\x04xxxx", 7.9, 7.5), "a real docx is compressed");
        assert!(!looks_encrypted(Path::new("photo.jpg"), b"\xFF\xD8\xFF\xE0", 7.95, 7.5));
        assert!(looks_encrypted(Path::new("notes.txt"), b"\x01\x02\x03\x04", 7.9, 7.5));
        assert!(!looks_encrypted(Path::new("notes.txt"), b"Dear", 4.5, 7.5));
        let mut d = detector();
        let fired = (0..30).filter_map(|i| d.on_encrypted_write(1_000 + i)).count();
        assert_eq!(fired, 1);
    }
}
