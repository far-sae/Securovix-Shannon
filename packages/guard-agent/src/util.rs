//! Small helpers: time, hashing, entropy, running system commands, paths.
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0xf) as usize] as char);
    }
    out
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// SHA-256 of a file, streamed, refusing anything larger than `max` bytes.
pub fn sha256_file(path: &Path, max: u64) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > max {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex(&hasher.finalize()))
}

/// Shannon entropy in bits per byte (0..=8). Encrypted data sits near 8.
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts.iter().filter(|c| **c > 0).map(|c| {
        let p = *c as f64 / len;
        -p * p.log2()
    }).sum()
}

pub fn extension(path: &Path) -> String {
    path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default()
}

/// Runs a system command and returns (success, combined output). Never goes through a shell.
pub fn run(program: &str, args: &[&str]) -> (bool, String) {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    match cmd.output() {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            (out.status.success(), text)
        }
        Err(e) => (false, e.to_string()),
    }
}

/// Where the agent keeps its configuration, quarantine and state.
pub fn home() -> PathBuf {
    if let Ok(dir) = std::env::var("SECUROVIX_GUARD_HOME") {
        return PathBuf::from(dir);
    }
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        PathBuf::from(base).join("Securovix").join("Guard")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Securovix Guard")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/securovix-guard")
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_tells_text_from_random() {
        let text = b"The quarterly report shows revenue grew in every region. ".repeat(40);
        assert!(entropy(&text) < 5.0);
        let mut x: u32 = 0x1234_5678;
        let random: Vec<u8> = (0..4096).map(|_| { x ^= x << 13; x ^= x >> 17; x ^= x << 5; (x & 0xff) as u8 }).collect();
        assert!(entropy(&random) > 7.8);
        assert_eq!(entropy(&[]), 0.0);
    }

    #[test]
    fn hashes_and_hex() {
        assert_eq!(sha256_bytes(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
        assert_eq!(truncate("héllo", 2), "h");
    }
}
