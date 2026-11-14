# Securovix Guard agent

The endpoint half of Guard (Phase 2). One small binary (about 2 MB) for Windows and Linux; macOS
builds on a Mac or in CI (`.github/workflows/guard-agent.yml`).

## What it does

| Area | How |
|---|---|
| Processes | New processes every 2 s with command line, parent chain, user and SHA-256 of the program. On Windows with Sysmon installed it reads Sysmon instead, which also catches programs that run for under a second and any process opening LSASS. |
| Autostart | New Run keys, services and scheduled tasks (Windows); cron, systemd units and autostart entries (Linux); launch agents (macOS). |
| Logons | Remote Desktop logons from the Windows Security log, for the "one address into many machines" rule. |
| Ransomware | Watches document folders (Documents, Desktop, Downloads, Pictures of every profile, plus any extra folders in the policy) and plants two hidden decoy files in each. Signals: a decoy is touched; 20 files renamed to one new extension; 30 files rewritten with encrypted-looking content (high entropy, or a .docx/.pdf/.jpg whose header no longer matches). |
| Local stop | On a decoy hit, or renames backed by encrypted writes, the agent stops the program on the spot, but only one it can name with confidence: started in the last 30 minutes AND running from a user-writable folder (Downloads, Temp, AppData\Roaming, Public, ProgramData, /tmp). Installed applications are never stopped automatically. Otherwise it reports and the server recommends isolating the machine. |
| Known malware | Hashes the sandbox proved malicious (shared across every customer) are stopped and quarantined when they run. |
| Responses | Isolate / reconnect (only the Securovix server stays reachable), stop a process tree, quarantine / restore a file, send a file to the sandbox. |
| Tamper | Runs as a service that Windows/systemd/launchd restarts; a deliberate stop or uninstall is reported first; the server raises an alert when a machine stops checking in. |

Isolation saves the exact firewall state and restores exactly that: on Windows
`netsh advfirewall export` / `import`; on Linux a separate nftables table that release simply
deletes. macOS isolation is not implemented yet and reports a failure rather than pretending.

## Install

On the Guard page, **Add a machine** shows the command with a one-time enrollment token:

```powershell
# Windows, PowerShell as administrator
.\securovix-guard.exe install --server https://YOUR-DASHBOARD --token svxe_...
```

```sh
# Linux
sudo ./securovix-guard install --server https://YOUR-DASHBOARD --token svxe_...
```

`securovix-guard uninstall` removes it (and lifts isolation). `securovix-guard status` shows the
enrollment. The credential is stored under `C:\ProgramData\Securovix\Guard` or
`/var/lib/securovix-guard`, readable only by SYSTEM/root and administrators.

## Test it safely

```sh
securovix-guard selftest-ransomware --dir "C:\Users\you\Documents\guard-test" --files 60
```

Creates its own 60 files in a new folder, then overwrites and renames them one by one like
ransomware. Run it from a Downloads/Temp copy of the binary so it looks like a dropper; Guard
should stop it well before 50 files (23 in our test on Windows 11).

## Build

```sh
sh packages/guard-agent/build/build.sh     # Docker: tests, then Linux + Windows binaries in dist/
```

## Measured (Windows 11, this repo's live test)

0.2–0.5% CPU, 13 MB memory; ransomware rehearsal stopped after 23 of 60 files in 7 seconds;
kill, quarantine/restore and command-line detections confirmed end to end. Linux isolation
verified in containers: the Guard server stayed reachable, everything else was blocked, and
release removed the rules.

## Not yet

- Kernel telemetry (ETW consumer, eBPF, Endpoint Security framework). Polling plus Sysmon covers
  most of it; very short-lived processes are missed without Sysmon.
- Code signing. Sign the Windows and macOS binaries before giving them to customers, or
  SmartScreen/Gatekeeper and some antivirus products will block them.
- macOS isolation and an MSI/pkg installer for Intune or Jamf.
