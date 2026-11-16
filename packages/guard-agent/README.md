# Securovix Guard agent

The endpoint half of Guard (Phase 2). One small binary (about 2 MB) for Windows and Linux; macOS
builds on a Mac or in CI (`.github/workflows/guard-agent.yml`).

## What it does

| Area | How |
|---|---|
| Processes | New processes every 2 s with command line, parent chain, user and SHA-256 of the program. On Windows with Sysmon installed it reads Sysmon instead, which also catches programs that run for under a second and any process opening LSASS. |
| Autostart | New Run keys, services, scheduled tasks and Startup-folder files (Windows); every job of a cron file, systemd units, shell profiles, `/etc/ld.so.preload` and autostart entries (Linux); launch agents (macOS). Each new entry is sent with what it runs, who signed the program (Windows), where a Store app shortcut really points, and which package owns the file (Linux), so the server can tell installed software from something worth a look. |
| Logons | Remote Desktop logons from the Windows Security log, for the "one address into many machines" rule. |
| Ransomware | Watches document folders (Documents, Desktop, Downloads, Pictures of every profile, plus any extra folders in the policy) and plants two hidden decoy files in each. Signals: a decoy is rewritten, renamed or deleted (a decoy whose attributes were merely touched by a backup or antivirus scan is ignored); 20 documents renamed to an unfamiliar or added extension (`report.docx.locked`), whatever the extension; 30 documents rewritten with encrypted-looking content (high entropy, or a .docx/.pdf/.jpg whose header no longer matches). Only file types whose normal content is known count, and tool folders (`.git`, `node_modules`, caches) are skipped, so a git checkout, a package install, photos renamed from .jpeg to .jpg or downloads finishing do not look like ransomware. |
| Local stop | On a decoy hit, or renames backed by encrypted writes, the agent stops the program on the spot, but only one it can name with confidence: started in the last 30 minutes AND running from a user-writable folder (Downloads, Temp, AppData\Roaming, Public, ProgramData, /tmp). Installed applications are never stopped automatically. Otherwise it reports and the server recommends isolating the machine. |
| Known malware | Hashes the sandbox proved malicious (shared across every customer) are stopped and quarantined when they run. |
| Responses | Isolate / reconnect (only the Securovix server stays reachable), stop a process tree, quarantine / restore a file, send a file to the sandbox. |
| Tamper | Runs as a service that Windows/systemd/launchd restarts. An uninstall is reported at once. A stop by hand is reported if the agent stays down for three minutes, or comes back unchanged (someone switched Guard off for a while); a stop that is followed by a newer version or a reinstall is an update and raises nothing. |
| Offline | Before a shutdown or a sleep the agent says so, and the machine shows as offline with the reason. Silence without that notice raises a "machine stopped reporting" notice only for machines marked **Alert if offline** (on by default for Linux and Windows Server, off for PCs and laptops). |

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

**Updating.** Run the same install command again (with a new token from **Add a machine**). It
stops the running agent, replaces the program and starts the new one; the machine keeps its
record and history on the Guard page.

`securovix-guard inspect-autostart "<command>"` (Windows) prints what Guard would report about an
autostart command: the program it starts and who signed it. It only reads and needs no
administrator rights.

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

## Accuracy

Detection is measured, not assumed. `packages/dashboard/guard/accuracy-corpus.mjs` holds labelled
samples: harmless activity that must stay quiet (many are real false alarms Guard once raised),
attack techniques that must be caught at a stated severity, and a few behaviours that admins and
attackers share and are reported on purpose. `guard-accuracy.test.mjs` fails the build when a
harmless sample alerts or an attack is missed. When Guard gets something wrong in the field, add
the sample first, then fix the rule.

What a customer can do about an alert that is correct by behaviour but expected on their
machines (their own launcher script, an admin tool): **This is expected** on the alert stops
Guard reporting that exact command or file on every machine. Ransomware, credential theft and
other critical alerts cannot be silenced this way.

## Not yet

- Kernel telemetry (ETW consumer, eBPF, Endpoint Security framework). Polling plus Sysmon covers
  most of it; very short-lived processes are missed without Sysmon.
- Code signing. Sign the Windows and macOS binaries before giving them to customers, or
  SmartScreen/Gatekeeper and some antivirus products will block them.
- macOS isolation and an MSI/pkg installer for Intune or Jamf.
