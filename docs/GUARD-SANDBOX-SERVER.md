# Guard malware sandbox: setting up your own server

Guard can send unknown programs to a sandbox: a server that runs each file inside a throwaway
Windows machine, watches what it does, and reports back. When the verdict is "malicious", Guard
blocks that exact file on every machine. The sandbox Guard speaks to is
[CAPE](https://github.com/kevoreilly/CAPEv2) (open source).

**Read this first**

- This is the hardest setup in the product. Allow half a day. Most of it is waiting; the Windows
  part needs care.
- **This guide has not been run end to end.** The Guard side is tested against a simulated CAPE
  server. The CAPE steps below come from CAPE's official documentation and installer scripts as
  read in November 2026, and CAPE changes often. Where its own instructions disagree with each
  other, this guide says so (look for **Check**).
- A cloud server (Hetzner Cloud, the kind `securovix-sandbox` is) **cannot** do this: it cannot
  run virtual machines inside itself. You need a dedicated (bare-metal) server.
- The sandbox runs real malware. Keep it on its own server, with nothing else on it.

## 1. What to rent

| Need | Minimum | Comfortable |
|---|---|---|
| Server type | Dedicated / bare metal, Intel or AMD with virtualisation (VT-x / AMD-V) | Same |
| Memory | 16 GB | 32 GB or more |
| Disk | 250 GB SSD | 500 GB SSD |
| System | Ubuntu 24.04 LTS | Same |

At Hetzner these are under **Robot** (robot.hetzner.com), not the Cloud console: either
"Dedicated root servers" or the cheaper "Server auction". Choose Ubuntu 24.04 during the order,
and add the same SSH key you use for your other server. CAPE's documentation states no hardware
minimum; the numbers above are what one Windows analysis machine plus CAPE's databases need.

You also need:

- **A name for the server**, for example `cape.yourdomain.com`, pointing at its address (an `A`
  record at your DNS provider). The dashboard reaches the sandbox over HTTPS, and the
  certificate needs a name.
- **A Windows 10 installation image (ISO).** Microsoft offers a 90-day evaluation image of
  Windows 10 Enterprise. You are responsible for the Windows licence.
- **A VNC viewer on your PC** (for example TigerVNC), to see the Windows screen while you set it
  up.

## 2. Install KVM and CAPE on the server

Connect as root (`ssh root@SERVER_ADDRESS`), then:

```sh
apt update && apt -y upgrade
egrep -c '(vmx|svm)' /proc/cpuinfo        # must print a number above 0
adduser --disabled-password --gecos "" cape
mkdir -p /root/cape-install && cd /root/cape-install
wget https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/installer/kvm-qemu.sh
wget https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/installer/cape2.sh
chmod a+x kvm-qemu.sh cape2.sh
```

If the second command prints `0`, the server cannot run virtual machines: stop and ask the
provider to enable virtualisation, or pick another server.

**Edit before running** (use `nano`, save with Ctrl+O, Enter, Ctrl+X):

1. In `kvm-qemu.sh`, replace every `<WOOT>` with any four letters of your choice, the same four
   each time (for example `ASUS`). These become the "hardware names" the Windows machine sees,
   so malware is less likely to notice it is in a sandbox.

   ```sh
   sed -i 's/<WOOT>/ASUS/g' kvm-qemu.sh
   ```

2. In `cape2.sh`, near the top, set:
   - `PASSWD=` to a long password of your own (it is the database password),
   - `NETWORK_IFACE=virbr0` (the network the Windows machine will be on),
   - `IFACE_IP="192.168.122.1"` (the server's address on that network).

Now install. Each step takes 15 to 40 minutes and each one ends with a restart:

```sh
./kvm-qemu.sh all cape 2>&1 | tee kvm-qemu.log
reboot
```

Reconnect, then:

```sh
cd /root/cape-install
./cape2.sh all 192.168.122.1 2>&1 | tee cape.log
reboot
```

**Check.** CAPE's documentation writes this last command as `./cape2.sh all cape`, while the
script's own help says the second word is the interface address
(`Usage: cape2.sh <command> <iface_ip>`). Run `./cape2.sh -h` first and follow what the script
you downloaded says.

**Check.** `cape2.sh` has a line `LIB_VERSION=` with the comment "Must match libvirt version!".
After the first restart, run `virsh --version` and make that line match before running
`cape2.sh`.

After the second restart, CAPE lives in `/opt/CAPEv2` and runs as the user `cape`. Four services
should be present:

```sh
systemctl status cape cape-processor cape-rooter cape-web --no-pager | grep -E 'service|Active'
```

It is normal for `cape` to be failing at this point: it has no Windows machine yet.

## 3. Close the server to the internet

CAPE's web page has no sign-in by default. Until step 6, nothing but SSH should be reachable:

```sh
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw enable
```

## 4. Build the Windows analysis machine

Copy the Windows ISO to the server (from your PC, in PowerShell):

```
scp C:\path\to\Windows10.iso root@SERVER_ADDRESS:/var/lib/libvirt/images/win10.iso
```

On the server, create the machine. The disk must be in QCOW2 format, or snapshots do not work:

```sh
qemu-img create -f qcow2 /var/lib/libvirt/images/win10.qcow2 80G
virt-install --name win10 --memory 4096 --vcpus 2 --os-variant win10 \
  --disk path=/var/lib/libvirt/images/win10.qcow2,format=qcow2,bus=sata \
  --cdrom /var/lib/libvirt/images/win10.iso \
  --network network=default,model=e1000 \
  --graphics vnc,listen=127.0.0.1,port=5900 --noautoconsole
```

To see its screen, open a second PowerShell window on your PC and leave it open:

```
ssh -L 5900:127.0.0.1:5900 root@SERVER_ADDRESS
```

Then open your VNC viewer and connect to `localhost:5900`. Install Windows 10 with a local
account (no Microsoft account) and no password prompts you will forget.

Inside Windows, once it is installed:

1. **Fixed address.** Network settings, IPv4, manual: address `192.168.122.105`, mask
   `255.255.255.0`, gateway `192.168.122.1`, DNS `8.8.8.8`. CAPE does not support automatic
   addresses.
2. **Python.** Install Python 3.11 or 3.12 from python.org (CAPE asks for a version above 3.10
   and below 3.13). Tick "Add python.exe to PATH". Then in a command prompt:
   `python -m pip install --upgrade pip` and `python -m pip install Pillow`.
3. **7-Zip.** Install it (CAPE uses it to open archives inside the machine).
4. **Switch protections off.** This machine exists to be infected:
   - Windows Defender Firewall: off for all networks.
   - Windows Security, Virus and threat protection: real-time protection off, tamper
     protection off.
   - Windows Update service: Startup type "Disabled", then Stop.
   - User Account Control: slider to "Never notify".
   - In an administrator command prompt: `netsh interface teredo set state disabled`.
5. **The CAPE agent.** On the server the file is `/opt/CAPEv2/agent/agent.py`. Copy it into the
   Windows machine (the simplest way: on the server run
   `cd /opt/CAPEv2/agent && python3 -m http.server 8080 --bind 192.168.122.1`, and in Windows
   open `http://192.168.122.1:8080/agent.py` in the browser and save it; then stop that command
   with Ctrl+C). Save it as `C:\agent.pyw` (the `.pyw` ending stops a black window appearing).
6. **Start the agent at sign-in, as administrator.** Task Scheduler, Create Basic Task, trigger
   "When I log on", action "Start a program", program `C:\agent.pyw`. Open the task's
   Properties and tick **Run with highest privileges**. CAPE's documentation is firm that the
   agent must run elevated.
7. **Restart Windows, sign in, wait a minute.** From the server, check the agent answers:

   ```sh
   curl 192.168.122.105:8000
   ```

   It should print a short JSON message. If it does not, the task or the firewall is wrong.
8. **Take the snapshot while Windows is running**, signed in, with the agent running:

   ```sh
   virsh snapshot-create-as --domain win10 --name clean
   virsh shutdown win10
   ```

## 5. Tell CAPE about the machine

Settings live in `/opt/CAPEv2/conf/`. Edit them as the `cape` user, for example
`sudo -u cape nano /opt/CAPEv2/conf/kvm.conf`. Every file is commented; the lines below are the
ones that matter. **Check** the comments in your copy, because key names change between
versions.

`kvm.conf`: the section name must be exactly the machine name from `virsh list --all`.

```ini
[kvm]
machines = win10
interface = virbr0

[win10]
label = win10
platform = windows
ip = 192.168.122.105
arch = x64
snapshot = clean
```

`cuckoo.conf`:

```ini
[cuckoo]
machinery = kvm

[resultserver]
ip = 192.168.122.1
```

`api.conf`: require a token, and raise the limits. The defaults (2 uploads and 6 reports a
minute) are too low for an automated client.

```ini
[api]
token_auth_enabled = yes

[filecreate]
auth_only = yes
rps = 5/s
rpm = 60/m

[taskstatus]
auth_only = yes
rps = 10/s

[taskreport]
auth_only = yes
rps = 5/s
rpm = 120/m
```

`web.conf`: in `[general]` set `behind_proxy = yes` (step 6 puts a proxy in front), and in
`[web_auth]` set `enabled = yes` so the web page needs a sign-in.

Create a user and its API token:

```sh
cd /opt/CAPEv2/web
sudo -u cape poetry run python3 manage.py createsuperuser
sudo -u cape poetry run python3 manage.py drf_create_token YOUR_USER_NAME
```

The second command prints the token. Keep it; it is the password to your sandbox.

Restart and test with a harmless file:

```sh
systemctl restart cape cape-processor cape-rooter cape-web
journalctl -u cape -n 30 --no-pager
curl -H "Authorization: Token YOUR_TOKEN" -F file=@/usr/bin/ls http://127.0.0.1:8000/apiv2/tasks/create/file/
```

The last command should answer with a task number. Use it here; after a few minutes the status
becomes `reported`:

```sh
curl -H "Authorization: Token YOUR_TOKEN" http://127.0.0.1:8000/apiv2/tasks/status/1/
```

Do not continue until a task reaches `reported`. If it stays `pending`, read
`journalctl -u cape -n 80`: it almost always names the problem (machine name, snapshot name,
address, or the agent not answering).

## 6. Let the dashboard reach it, safely

Only the API is published, over HTTPS, and only with the token. Caddy gets the certificate by
itself.

```sh
apt -y install caddy
cat > /etc/caddy/Caddyfile <<'EOF'
cape.yourdomain.com {
    @api path /apiv2/*
    handle @api {
        reverse_proxy 127.0.0.1:8000
    }
    handle {
        respond 404
    }
}
EOF
systemctl restart caddy
ufw allow 80/tcp
ufw allow 443/tcp
```

Replace `cape.yourdomain.com` with your server's name. From your PC, this must print `401` or
`403` (refused without a token), not `200`:

```
curl.exe -s -o NUL -w "%{http_code}" https://cape.yourdomain.com/apiv2/tasks/status/1/
```

If it prints `200`, token sign-in is not on: go back to `api.conf` before going further.

The CAPE web page itself is not published. To look at it, tunnel it to your PC
(`ssh -L 8000:127.0.0.1:8000 root@SERVER_ADDRESS`) and open `http://localhost:8000`.

## 7. Connect Guard

Three settings on the Dashboard service (Railway, Variables):

| Name | Value |
|---|---|
| `SHANNON_CAPE_URL` | `https://cape.yourdomain.com` |
| `SHANNON_CAPE_TOKEN` | the token from step 5 |
| `SHANNON_CAPE_TIMEOUT_SEC` | leave unset (180 seconds per file) |

After the Dashboard restarts, the Guard page shows **Malware sandbox · connected**. Then:

- Under **Protection settings**, "Send unknown programs started from Downloads/Temp to the
  sandbox" can be ticked. It is off until a sandbox is connected.
- To test, open any incident with a file and click **Send the file to the malware sandbox**, or
  start a harmless downloaded program on a machine with the agent. The file appears in the
  sandbox list as "analyzing", then with a verdict a few minutes later.

## What it does once connected

- Programs started from Downloads or Temp folders that Guard has not seen before are uploaded
  (up to 32 MB) and analysed. The agent does not wait for the verdict; the program keeps
  running meanwhile.
- A "malicious" verdict adds the file's fingerprint to the blocked list. From then on every
  machine stops and quarantines that file when it runs, and the machine that sent it gets an
  incident.
- Only the fingerprint, verdict and family name are shared between organizations, never the
  file name or who sent it.

## Keeping it healthy

- One Windows machine analyses one file at a time, about three minutes each. If many files
  queue up, add a second machine (repeat step 4 with another name and address, list both in
  `kvm.conf`).
- If the evaluation copy of Windows expires, rebuild the machine and retake the snapshot.
- Update CAPE only when you have time to fix what breaks: `cd /opt/CAPEv2 && sudo -u cape git pull`
  followed by the steps in CAPE's own upgrade notes.
- Never browse, sign in to accounts, or keep anything private on this server.
