//! Securovix Guard endpoint agent.
//!
//!   securovix-guard install --server https://origin.securovix.com --token svxe_...   (admin/root)
//!   securovix-guard uninstall
//!   securovix-guard run                    foreground, uses the saved configuration
//!   securovix-guard enroll --server URL --token svxe_...   enroll without installing a service
//!   securovix-guard status
//!   securovix-guard selftest-ransomware --dir <new empty folder in a watched place> [--files 60]
// Windows-only helpers (registry and event-log parsing, netsh plans) are unit-tested everywhere
// but only called on Windows.
#![cfg_attr(not(windows), allow(dead_code))]
mod agent;
mod api;
mod config;
mod event;
mod filemon;
mod persistence;
mod procmon;
mod ransomware;
mod respond;
mod service;
mod shared;
#[cfg(unix)]
mod sig;
mod util;
mod winlog;

use std::sync::atomic::Ordering;
use std::sync::Arc;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn usage() -> ! {
    eprintln!(
        "Securovix Guard {}\n\nUsage:\n  securovix-guard install --server URL --token ENROLL_TOKEN\n  securovix-guard uninstall\n  securovix-guard run\n  securovix-guard enroll --server URL --token ENROLL_TOKEN\n  securovix-guard status\n  securovix-guard selftest-ransomware --dir NEW_EMPTY_FOLDER [--files N]",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2)
}

fn require_server_and_token(args: &[String]) -> (String, String) {
    match (arg(args, "--server"), arg(args, "--token")) {
        (Some(s), Some(t)) if s.starts_with("http://") || s.starts_with("https://") => (s, t),
        _ => usage(),
    }
}

/// A harmless ransomware rehearsal: creates its own files in a new folder, then "encrypts"
/// (overwrites with random bytes) and renames them one by one, like ransomware would. It never
/// touches a file it did not create. Run it in a watched folder; Guard should stop it.
fn selftest(args: &[String]) {
    let Some(dir) = arg(args, "--dir").map(std::path::PathBuf::from) else { usage() };
    let files: usize = arg(args, "--files").and_then(|n| n.parse().ok()).unwrap_or(60).clamp(10, 500);
    if dir.exists() && std::fs::read_dir(&dir).map(|mut d| d.next().is_some()).unwrap_or(true) {
        eprintln!("{} must be a new or empty folder; the test only works on files it creates.", dir.display());
        std::process::exit(2);
    }
    std::fs::create_dir_all(&dir).expect("create test folder");
    let text = "Quarterly figures for the board. Revenue, costs and forecasts by region.\n".repeat(120);
    for i in 0..files {
        std::fs::write(dir.join(format!("report-{i:03}.txt")), &text).expect("write test file");
    }
    std::thread::sleep(std::time::Duration::from_secs(3));
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ util::now_ms();
    for i in 0..files {
        let path = dir.join(format!("report-{i:03}.txt"));
        let noise: Vec<u8> = (0..text.len()).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 }).collect();
        std::fs::write(&path, noise).expect("overwrite test file");
        std::fs::rename(&path, dir.join(format!("report-{i:03}.txt.locked"))).expect("rename test file");
        println!("encrypted {}/{files}", i + 1);
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    println!("Finished all {files} files: Guard did NOT stop this test. Check that the agent is running and watching {}.", dir.display());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("install") => {
            let (server, token) = require_server_and_token(&args);
            match service::install(&server, &token) {
                Ok(msg) => println!("{msg}"),
                Err(e) => {
                    eprintln!("Install failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("uninstall") => match service::uninstall() {
            Ok(msg) => println!("{msg}"),
            Err(e) => {
                eprintln!("Uninstall failed: {e}");
                std::process::exit(1);
            }
        },
        Some("enroll") => {
            let (server, token) = require_server_and_token(&args);
            match service::enroll(&server, &token) {
                Ok(c) => println!("Enrolled as {}. Start it with: securovix-guard run", c.agent_id),
                Err(e) => {
                    eprintln!("Enrollment failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("run") => {
            let Some(config) = config::Config::load() else {
                eprintln!("Not enrolled yet. Run: securovix-guard enroll --server URL --token TOKEN");
                std::process::exit(1)
            };
            println!("Securovix Guard {} running as {} against {}", env!("CARGO_PKG_VERSION"), config.agent_id, config.server);
            #[cfg(unix)]
            sig::install();
            let shared = Arc::new(shared::Shared::new(config));
            agent::run(shared.clone());
            shared.stop.store(true, Ordering::SeqCst);
        }
        #[cfg(windows)]
        Some("service") => {
            if let Err(e) = service::winservice::start() {
                eprintln!("This command is run by Windows as a service: {e}");
                std::process::exit(1);
            }
        }
        Some("status") => match config::Config::load() {
            Some(c) => println!("agent {}\nserver {}\nisolated {}\npolicy v{}\nknown-malicious hashes {}", c.agent_id, c.server, c.isolated, c.policy.version, c.hashes.len()),
            None => println!("not enrolled"),
        },
        Some("selftest-ransomware") => selftest(&args),
        // What Guard would report about an autostart command: the program it starts, where a
        // Store app shortcut points, and who signed it. Reads only; needs no administrator rights.
        #[cfg(windows)]
        Some("inspect-autostart") => {
            let command = args.get(2).cloned().unwrap_or_else(|| usage());
            let described = persistence::describe(event::Persistence { kind: "run-key".into(), name: "inspect".into(), command, ..Default::default() });
            println!("program   {}", persistence::locate_program(&described.command).unwrap_or_else(|| "(a bare name, found through PATH)".into()));
            println!("resolved  {}", described.resolved.as_deref().unwrap_or("-"));
            match described.signer {
                Some(s) => println!("signer    {} {}", s.status, s.subject.unwrap_or_default()),
                None => println!("signer    not checked (a protected folder, a shortcut, or no such file)"),
            }
        }
        _ => usage(),
    }
}
