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
deletes. The Linux table closes the input, output and forward paths, so containers and virtual
machines on the host are cut off too and published ports stop answering; Docker's own rules are
never edited. Isolation needs `nft` (the `nftables` package). macOS isolation is not implemented
yet and reports a failure rather than pretending.

## Install

On the Guard page, **Add a machine** shows one command per platform, already filled in with the
server address, the checksum of that server's build and an enrollment token:

```sh
# Linux (any distribution; the binary is static), as a user who can sudo
curl -fsSL https://YOUR-DASHBOARD/api/endpoint-agent/v1/download/linux -o securovix-guard \
  && echo "<sha256>  securovix-guard" | sha256sum -c - \
  && chmod +x securovix-guard \
  && sudo ./securovix-guard install --server https://YOUR-DASHBOARD --token svxe_...
```

```powershell
# Windows, PowerShell as administrator
Invoke-WebRequest https://YOUR-DASHBOARD/api/endpoint-agent/v1/download/windows -OutFile securovix-guard.exe -UseBasicParsing
if ((Get-FileHash securovix-guard.exe -Algorithm SHA256).Hash -ne '<SHA256>') { throw 'The download does not match the build on this server.' }
.\securovix-guard.exe install --server https://YOUR-DASHBOARD --token svxe_...
```

It installs to `/usr/local/bin/securovix-guard` with a systemd unit (`securovix-guard.service`),
or to `C:\Program Files\Securovix Guard` as the `SecurovixGuard` service, and starts with the
machine.

**Servers and Docker hosts.** A server has no Documents folder, so add its data folders on the
Guard page under **Protection settings → Extra folders to watch** (on a Docker host, the folders
you mount into containers). Machines pick up a new folder at their next check-in, no restart. The
agent sees container processes as ordinary processes of the host.

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

The production dashboard image builds the same two binaries itself (`Dockerfile.dashboard`, first
stage), so nothing has to be built or uploaded by hand for a deployment. The Linux binary targets
`x86_64-unknown-linux-musl`: fully static, no glibc version to match.

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
