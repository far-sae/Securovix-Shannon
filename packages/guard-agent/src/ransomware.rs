//! Local ransomware detector. Runs on the machine so it can stop encryption in seconds, without
//! waiting for the server. Signals:
//!   * a canary (decoy) file is changed, renamed or deleted -> act at once
//!   * many files renamed to the same new extension in a short window
//!   * many files rewritten with encrypted-looking content (high entropy, or a document whose
//!     header no longer matches its type)
//! Only canary hits and rename bursts backed by encrypted-looking writes stop a process; a burst
//! of high-entropy writes alone is reported but not acted on (backup and sync tools do that too).
//!
//! What counts is narrow on purpose. Random-looking content only means "encrypted" for a file
//! type whose normal content is known (a document, or a document with one more extension added:
//! report.docx.locked). A git checkout, an npm install or a game cache writes thousands of
//! compressed files that are none of those, and renaming photos from .jpeg to .jpg or a download
//! from .crdownload to .pdf is ordinary. Tool folders (.git, node_modules, caches) are skipped.
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

/// File types people keep their work in. Their normal content is known, so "now looks random"
/// means something.
const DATA_EXT: &[&str] = &[
    "doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm", "pdf", "txt", "rtf", "csv", "tsv", "odt", "ods", "odp", "md",
    "json", "xml", "html", "htm", "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "psd", "ai", "svg", "mp3", "wav", "mp4", "mov", "avi", "mkv", "zip", "rar",
    "7z", "sql", "db", "sqlite", "mdb", "accdb", "pst", "ost", "msg", "eml", "vsd", "vsdx", "dwg", "dxf", "indd", "key", "pages", "numbers", "tex", "py", "js",
    "ts", "java", "c", "cpp", "h", "cs", "go", "rs", "php", "rb", "kt", "swift",
];
/// Other extensions that are ordinary: renaming a document to one of these is not encryption.
const OTHER_KNOWN_EXT: &[&str] = &[
    "tmp", "bak", "old", "orig", "part", "partial", "crdownload", "download", "opdownload", "temp", "swp", "swo", "lock", "lck", "lnk", "url", "ini", "log",
    "dat", "bin", "exe", "dll", "msi", "iso", "img", "gz", "bz2", "xz", "zst", "tar", "tgz", "cab", "jar", "apk", "torrent", "ics", "vcf", "cfg", "conf",
    "yaml", "yml", "toml", "css", "scss", "less", "map", "woff", "woff2", "ttf", "otf", "ico", "webp", "heic", "heif", "raw", "cr2", "nef", "arw", "dng", "m4a",
    "m4v", "flac", "ogg", "webm", "wmv", "epub", "mobi", "azw3", "srt", "vtt", "sig", "asc", "sha256", "sha1", "md5", "sum", "patch", "diff", "rej", "idx",
    "pack", "rev",
];
/// Folders that belong to a tool, not to a person's documents.
const NOISY_DIRS: &[&str] = &[
    ".git", ".svn", ".hg", "node_modules", ".venv", "venv", "__pycache__", ".cache", ".gradle", ".m2", ".nuget", ".cargo", "target", ".next", ".vs", ".idea",
    "$recycle.bin", "appdata",
];

fn known_ext(ext: &str) -> bool {
    DATA_EXT.contains(&ext) || OTHER_KNOWN_EXT.contains(&ext)
}

/// True inside a version-control, package or cache folder.
pub fn noisy(path: &Path) -> bool {
    path.components().any(|c| NOISY_DIRS.contains(&c.as_os_str().to_string_lossy().to_lowercase().as_str()))
}

/// "report.docx.locked": a document with one more, unfamiliar extension added on the end.
pub fn appended_to_document(path: &Path) -> bool {
    let outer = crate::util::extension(path);
    let inner = path.file_stem().map(|stem| crate::util::extension(Path::new(stem))).unwrap_or_default();
    !outer.is_empty() && outer.len() <= 12 && DATA_EXT.contains(&inner.as_str()) && !known_ext(&outer)
}

/// A rename that looks like encryption: a document given an unfamiliar or an added extension.
pub fn suspicious_rename(old: &Path, new: &Path) -> bool {
    let (from, to) = (crate::util::extension(old), crate::util::extension(new));
    if to.is_empty() || to == from || to.len() > 12 || noisy(new) {
        return false;
    }
    appended_to_document(new) || (DATA_EXT.contains(&from.as_str()) && !known_ext(&to))
}

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
    // Random-looking content only says something for a type whose normal content is known.
    if !(DATA_EXT.contains(&ext.as_str()) || appended_to_document(path)) {
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
        // A decoy that was rewritten or renamed was treated like a document by something working
        // through the folder. One that was only deleted may be a person clearing the folder out:
        // reported, but no process is stopped for it.
        Some(Verdict { reason: format!("a decoy (canary) file was {change}"), files: 1, kill: change != "deleted" })
    }

    pub fn on_rename(&mut self, now: u64, old: &Path, new: &Path) -> Option<Verdict> {
        if !suspicious_rename(old, new) {
            return None;
        }
        let ext = crate::util::extension(new);
        self.trim(now);
        self.renames.push_back((now, ext.clone()));
        // Every suspicious rename counts, whatever it was renamed to: some ransomware gives each
        // file its own random extension.
        let total = self.renames.len();
        if total < self.policy.rename_burst.max(5) || self.quiet("rename", now) {
            return None;
        }
        let same = self.renames.iter().filter(|(_, e)| *e == ext).count();
        // Renaming alone can be a batch tool; renaming plus encrypted-looking writes is not.
        let kill = self.writes.len() >= 5 || total >= self.policy.rename_burst * 2;
        let reason = if same * 2 >= total {
            format!("{same} documents renamed to \".{ext}\" within {} seconds", self.policy.window_seconds)
        } else {
            format!("{total} documents renamed to unfamiliar file types within {} seconds", self.policy.window_seconds)
        };
        Some(Verdict { reason, files: total, kill })
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
    fn a_rename_burst_alone_is_reported_not_killed() {
        let mut d = detector();
        let mut verdict = None;
        for i in 0..20 {
            verdict = verdict.or(d.on_rename(1_000 + i, Path::new(&format!("plan{i}.xlsx")), Path::new(&format!("plan{i}.xlsx.vault"))));
        }
        let v = verdict.unwrap();
        assert!(!v.kill, "no encrypted-looking writes behind it");
    }

    #[test]
    fn ordinary_renames_are_not_ransomware() {
        let mut d = detector();
        for i in 0..200u64 {
            assert!(d.on_rename(1_000 + i, Path::new(&format!("C:/p/img{i}.jpeg")), Path::new(&format!("C:/p/img{i}.jpg"))).is_none(), "photos to another ordinary type");
            assert!(d.on_rename(1_000 + i, Path::new(&format!("C:/d/r{i}.pdf.crdownload")), Path::new(&format!("C:/d/r{i}.pdf"))).is_none(), "a download finishing");
            assert!(d.on_rename(1_000 + i, Path::new(&format!("C:/d/~WRD{i}.tmp")), Path::new(&format!("C:/d/minutes{i}.docx"))).is_none(), "Word saving");
            assert!(d.on_rename(1_000 + i, Path::new(&format!("C:/d/plan{i}.xlsx")), Path::new(&format!("C:/d/plan{i}.xlsx.bak"))).is_none(), "backup copies");
            assert!(d.on_rename(1_000 + i, Path::new(&format!("C:/d/app/.git/objects/tmp_obj_{i}")), Path::new(&format!("C:/d/app/.git/objects/ab/{i}.xyz"))).is_none(), "a git checkout");
        }
    }

    #[test]
    fn a_different_extension_for_every_file_still_counts() {
        let mut d = detector();
        for i in 0..6 {
            d.on_encrypted_write(900 + i);
        }
        let mut verdict = None;
        for i in 0..20u64 {
            verdict = verdict.or(d.on_rename(1_000 + i, Path::new(&format!("C:/d/f{i}.docx")), Path::new(&format!("C:/d/f{i}.x{i}q"))));
        }
        let v = verdict.expect("20 documents renamed to 20 different unfamiliar types");
        assert!(v.kill);
        assert!(v.reason.contains("unfamiliar file types"), "{}", v.reason);
    }

    #[test]
    fn only_documents_can_look_encrypted() {
        assert!(!looks_encrypted(Path::new("C:/d/app/.git/objects/ab/cdef0123"), &[7u8; 600], 7.95, 7.5), "a git object: compressed, no extension");
        assert!(!looks_encrypted(Path::new("C:/d/game/chunk_3.pak"), &[7u8; 600], 7.99, 7.5), "a program's own compressed data");
        assert!(looks_encrypted(Path::new("C:/d/report.docx.crypt"), &[7u8; 600], 7.9, 7.5), "a document with an extension added");
        assert!(looks_encrypted(Path::new("C:/d/notes.csv"), &[7u8; 600], 7.9, 7.5));
        assert!(noisy(Path::new("C:/Users/amy/Documents/site/node_modules/pkg/a.node")));
        assert!(noisy(Path::new("/home/amy/Documents/app/.git/objects/ab/cd")));
        assert!(!noisy(Path::new("C:/Users/amy/Documents/budget.xlsx")));
        assert!(appended_to_document(Path::new("q3.xlsx.locked")));
        assert!(!appended_to_document(Path::new("q3.xlsx.bak")));
        assert!(!appended_to_document(Path::new("archive.tar.gz")));
    }

    #[test]
    fn a_deleted_decoy_is_reported_but_stops_nothing() {
        let mut d = detector();
        assert!(!d.on_canary(1_000, "deleted").unwrap().kill);
        assert!(d.on_canary(40_000, "modified").unwrap().kill);
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
