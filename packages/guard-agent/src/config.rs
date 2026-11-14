//! Agent configuration and the policy pushed by the server. Stored as JSON under util::home(),
//! readable only by SYSTEM/root and administrators (set at install time).
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", default)]
pub struct RansomwarePolicy {
    pub auto_kill: bool,
    pub rename_burst: usize,
    pub entropy_burst: usize,
    pub window_seconds: u64,
    pub high_entropy: f64,
}

impl Default for RansomwarePolicy {
    fn default() -> Self {
        RansomwarePolicy { auto_kill: true, rename_burst: 20, entropy_burst: 30, window_seconds: 30, high_entropy: 7.5 }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", default)]
pub struct Policy {
    pub version: u64,
    pub poll_seconds: u64,
    pub flush_seconds: u64,
    pub watch_user_folders: bool,
    pub extra_watch: Vec<String>,
    pub canaries: bool,
    pub ransomware: RansomwarePolicy,
    pub quarantine_known_malware: bool,
    pub auto_submit_executables: bool,
    pub use_sysmon: bool,
    pub allow: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            version: 0,
            poll_seconds: 10,
            flush_seconds: 5,
            watch_user_folders: true,
            extra_watch: vec![],
            canaries: true,
            ransomware: RansomwarePolicy::default(),
            quarantine_known_malware: true,
            auto_submit_executables: false,
            use_sysmon: true,
            allow: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub server: String,
    pub agent_id: String,
    pub token: String,
    pub policy: Policy,
    pub hash_version: u64,
    pub hashes: Vec<String>,
    pub isolated: bool,
}

pub fn path() -> PathBuf {
    crate::util::home().join("config.json")
}

impl Config {
    pub fn load() -> Option<Config> {
        let text = std::fs::read_to_string(path()).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let dir = crate::util::home();
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join("config.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap_or_default())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(tmp, path())
    }

    pub fn hash_set(&self) -> HashSet<String> {
        self.hashes.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_server_policy_and_fills_gaps() {
        let p: Policy = serde_json::from_str(r#"{"version":3,"pollSeconds":5,"ransomware":{"autoKill":false},"unknownField":1}"#).unwrap();
        assert_eq!(p.version, 3);
        assert_eq!(p.poll_seconds, 5);
        assert!(!p.ransomware.auto_kill);
        assert_eq!(p.ransomware.rename_burst, 20, "missing fields keep their defaults");
        assert!(p.canaries);
    }
}
