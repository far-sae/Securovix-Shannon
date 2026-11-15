//! Installing the agent as a service that restarts itself, and (on Windows) running as one.
use crate::config::Config;
use crate::util::{home, run};
use std::path::PathBuf;

pub fn machine_id() -> String {
    #[cfg(windows)]
    let raw = run("reg", &["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"]).1;
    #[cfg(target_os = "macos")]
    let raw = run("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]).1;
    #[cfg(all(unix, not(target_os = "macos")))]
    let raw = std::fs::read_to_string("/etc/machine-id").unwrap_or_default();
    let host = sysinfo::System::host_name().unwrap_or_default();
    // Hashed so the raw hardware identifier never leaves the machine.
    crate::util::sha256_bytes(format!("{}|{}", raw.trim(), host).as_bytes())[..32].to_string()
}

pub fn enroll(server: &str, enroll_token: &str) -> Result<Config, String> {
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "unknown".into());
    let enrolled = crate::api::Client::new(server, "").enroll(enroll_token, &hostname, &machine_id())?;
    let config = Config { server: server.trim_end_matches('/').to_string(), agent_id: enrolled.agent_id, token: enrolled.token, policy: enrolled.policy, ..Default::default() };
    secure_home()?;
    config.save().map_err(|e| format!("could not save configuration: {e}"))?;
    Ok(config)
}

/// Only SYSTEM/root and administrators may read the agent's credential and quarantine.
fn secure_home() -> Result<(), String> {
    let dir = home();
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    if std::env::var("SECUROVIX_GUARD_HOME").is_ok() {
        return Ok(()); // a developer/test location chosen by the person running it: leave its permissions alone
    }
    #[cfg(windows)]
    {
        let d = dir.to_string_lossy().to_string();
        let (ok, out) = run("icacls", &[&d, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]);
        if !ok {
            return Err(format!("could not restrict {d}: {}", out.trim()));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn installed_binary() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into())).join("Securovix Guard").join("securovix-guard.exe")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/usr/local/bin/securovix-guard")
    }
}

pub fn install(server: &str, enroll_token: &str) -> Result<String, String> {
    let config = enroll(server, enroll_token)?;
    let target = installed_binary();
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    if me != target {
        std::fs::copy(&me, &target).map_err(|e| format!("could not copy the agent to {}: {e}", target.display()))?;
    }
    let bin = target.to_string_lossy().to_string();
    #[cfg(windows)]
    {
        let _ = run("sc", &["stop", "SecurovixGuard"]);
        let _ = run("sc", &["delete", "SecurovixGuard"]);
        let bin_path = format!("\"{bin}\" service");
        let (ok, out) = run("sc", &["create", "SecurovixGuard", "binPath=", &bin_path, "start=", "auto", "DisplayName=", "Securovix Guard"]);
        if !ok {
            return Err(format!("sc create failed: {}", out.trim()));
        }
        run("sc", &["description", "SecurovixGuard", "Securovix Guard endpoint protection. Stopping it alerts your security team."]);
        // Tamper protection: Windows restarts the service if it is killed.
        run("sc", &["failure", "SecurovixGuard", "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000"]);
        let (ok, out) = run("sc", &["start", "SecurovixGuard"]);
        if !ok {
            return Err(format!("sc start failed: {}", out.trim()));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let plist = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>com.securovix.guard</string><key>ProgramArguments</key><array><string>{bin}</string><string>run</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n");
        std::fs::write("/Library/LaunchDaemons/com.securovix.guard.plist", plist).map_err(|e| e.to_string())?;
        run("launchctl", &["load", "-w", "/Library/LaunchDaemons/com.securovix.guard.plist"]);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let unit = format!("[Unit]\nDescription=Securovix Guard endpoint agent\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart={bin} run\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n");
        std::fs::write("/etc/systemd/system/securovix-guard.service", unit).map_err(|e| e.to_string())?;
        run("systemctl", &["daemon-reload"]);
        let (ok, out) = run("systemctl", &["enable", "--now", "securovix-guard"]);
        if !ok {
            return Err(format!("systemctl enable failed: {}", out.trim()));
        }
    }
    Ok(format!("Installed and running as {} (agent {}).", bin, config.agent_id))
}

pub fn uninstall() -> Result<String, String> {
    if let Some(config) = Config::load() {
        let shared = std::sync::Arc::new(crate::shared::Shared::new(config.clone()));
        crate::agent::report_stop(&shared, "the agent is being uninstalled");
        if config.isolated {
            let _ = crate::respond::release(&serde_json::Value::Null);
        }
    }
    #[cfg(windows)]
    {
        run("sc", &["stop", "SecurovixGuard"]);
        run("sc", &["delete", "SecurovixGuard"]);
    }
    #[cfg(target_os = "macos")]
    {
        run("launchctl", &["unload", "-w", "/Library/LaunchDaemons/com.securovix.guard.plist"]);
        let _ = std::fs::remove_file("/Library/LaunchDaemons/com.securovix.guard.plist");
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        run("systemctl", &["disable", "--now", "securovix-guard"]);
        let _ = std::fs::remove_file("/etc/systemd/system/securovix-guard.service");
        run("systemctl", &["daemon-reload"]);
    }
    // Decoys in the policy's extra folders are removed too, not only those in document folders.
    let extra = Config::load().map(|c| c.policy.extra_watch).unwrap_or_default();
    for dir in crate::filemon::watch_dirs(true, &extra) {
        for name in crate::filemon::CANARY_NAMES {
            let _ = std::fs::remove_file(dir.join(name));
        }
    }
    let _ = std::fs::remove_file(crate::config::path());
    Ok("Securovix Guard was removed. The quarantine folder was kept.".into())
}

#[cfg(windows)]
pub mod winservice {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    define_windows_service!(ffi_service_main, service_main);

    pub fn start() -> Result<(), String> {
        service_dispatcher::start("SecurovixGuard", ffi_service_main).map_err(|e| e.to_string())
    }

    fn status(state: ServiceState) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() },
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        }
    }

    fn service_main(_args: Vec<std::ffi::OsString>) {
        let Some(config) = crate::config::Config::load() else { return };
        let shared = Arc::new(crate::shared::Shared::new(config));
        let s = shared.clone();
        let handler = move |control| match control {
            ServiceControl::Stop => {
                // Someone stopped Guard by hand: tell the server before going quiet.
                crate::agent::report_stop(&s, "the Guard service was stopped on this machine");
                s.stop.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Shutdown => {
                s.stop.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(handle) = service_control_handler::register("SecurovixGuard", handler) else { return };
        let _ = handle.set_service_status(status(ServiceState::Running));
        crate::agent::run(shared);
        let _ = handle.set_service_status(status(ServiceState::Stopped));
    }
}
