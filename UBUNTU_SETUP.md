# Run NetFlow Analyzer on Ubuntu

## Recommended launcher (Ubuntu 22.04 / 24.04 / 26.04)

From your checkout:

```bash
git pull --ff-only
bash run-ubuntu.sh
```

The launcher installs missing dependencies, uses `util-linux-extra` for `sg`,
configures capture group permissions, reuses an existing Zeek installation
(including Zeek 9), creates `.venv`, and opens the dashboard in your default
browser after startup. Your browser controls whether that opens a tab or window.
It asks for sudo only when system setup is needed; the web server runs as your
regular user. Clean `main` checkouts are updated with a fast-forward pull;
checkouts with local edits are run without pulling.
Keep the terminal open; Ctrl+C stops the server. On a headless Ubuntu server,
open the printed URL through an SSH tunnel as described below.

If Zeek packages are present but unusable, the launcher stops with a diagnostic
instead of installing a conflicting release train. `PCAP_ZEEK_BINARY` and
`PCAP_DUMPCAP_BINARY` can override the native executable paths.

The manual instructions below are for a **fresh Ubuntu 24.04 installation**.
If Zeek is already installed and working, skip step 2.

These commands target **Ubuntu 24.04 LTS**, with Python 3.12. For another Ubuntu
release, use its matching repository from the
[official Zeek package instructions](https://github.com/zeek/zeek/wiki/Binary-Packages).
Do not install packages from a different Ubuntu release.

## 1. Install Python and packet capture tools

```bash
sudo apt update
sudo apt install git python3 python3-venv python3-pip tshark curl gnupg
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark "$USER"
```

Choose **Yes** when asked whether non-superusers may capture packets.
Log out and log back in so the new group membership takes effect.
`tshark` installs Wireshark's `dumpcap` capture tool. Npcap and WSL are not
needed on native Ubuntu. Run the application as your regular user.

## 2. Install Zeek (Ubuntu 24.04 only)

The following uses Zeek's official package repository and scopes its signing
key to this repository:

```bash
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/Release.key \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/zeek-archive-keyring.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
  | sudo tee /etc/apt/sources.list.d/zeek.list
sudo apt update
sudo apt install zeek-8.0
/opt/zeek/bin/zeek --version
dumpcap -D
```

`dumpcap -D` should list adapters. If it reports permission denied, verify
`id -nG` includes `wireshark` after logging back in. Package background:
[Zeek installation](https://docs.zeek.org/en/current/install.html) and
[Wireshark capture permissions](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges).

## 3. Get the project and install Python dependencies

```bash
git clone https://github.com/UltraMax1623/netflow-backend.git
cd netflow-backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install httpx
python -m unittest discover -s tests -v
```

For an existing checkout, use `git pull --ff-only` instead of cloning.
The automated tests mock external capture/Zeek execution; they do not prove
adapter permissions or actual Zeek installation.

## 4. Start the application

```bash
export PCAP_ZEEK_RUNTIME=native
export PCAP_ZEEK_BINARY=/opt/zeek/bin/zeek
export PCAP_DUMPCAP_BINARY=/usr/bin/dumpcap
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** on the same Ubuntu computer.
Click **Refresh adapters**, select the active Wi-Fi/Ethernet adapter, then
**Start live capture**. Generate traffic by browsing a website. Section 4
updates when each capture and Zeek analysis completes.

For each new terminal, activate `.venv` and set the environment variables
above before starting the server. Use a single server worker.
For an Ubuntu server accessed remotely, forward its localhost port:
`ssh -L 8000:127.0.0.1:8000 user@ubuntu-host`, then open localhost in your browser.
Captured traffic belongs to the Ubuntu server, not the browser's computer.

## 5. Verify a real capture end to end

With the application running, open two more terminals.
In the first, generate known local HTTP traffic for 20 seconds:

```bash
for i in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8000/ >/dev/null
  sleep 1
done
```

Immediately run this in the second terminal (Ubuntu's loopback adapter is `lo`):

```bash
curl -fsS http://127.0.0.1:8000/api/live/capture \
  -H 'Content-Type: application/json' \
  -d '{"interface":"lo","seconds":5,"capture_filter":"tcp port 8000"}' \
  -o /tmp/netflow-live-result.json
python3 -c 'import json; r=json.load(open("/tmp/netflow-live-result.json")); print(r["summary"]); assert r["summary"]["connection_count"] > 0; assert r["nodes"]; print("Live capture and Zeek analysis passed")'
```

This tests real dumpcap execution, packet capture, Zeek analysis, and the API.
The final message should say `Live capture and Zeek analysis passed`.
A missing runtime or capture permission error must be fixed before calling
the installation verified.

## Current limits

- All charts, the graph and the assessment use the current capture's real data.
- Capture pauses during analysis. The graph shows only the most recent window.
- Stop waits for the current capture and analysis; it is not immediate.
- Capture windows stop after their duration, 25 MB, or 100,000 packets.
- Captures and analysis logs are temporary; no capture history is saved.
