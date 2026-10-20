#!/usr/bin/env bash
# Run with: bash run-ubuntu.sh
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ $(id -u) == 0 ]]; then
  echo "Run this script as your regular user; it requests sudo only for system setup."
  exit 1
fi
. /etc/os-release
if [[ ${ID:-} != ubuntu ]]; then
  echo "This launcher supports native Ubuntu."
  exit 1
fi

missing=()
command -v git >/dev/null || missing+=(git)
command -v curl >/dev/null || missing+=(curl)
command -v sg >/dev/null || missing+=(util-linux-extra)
command -v xdg-open >/dev/null || missing+=(xdg-utils)
command -v dumpcap >/dev/null || missing+=(tshark)
if ! python3 -c 'import venv, ensurepip' 2>/dev/null; then
  missing+=(python3 python3-venv python3-pip)
fi
if ((${#missing[@]})); then
  sudo apt-get update
  echo 'wireshark-common wireshark-common/install-setuid boolean true' | sudo debconf-set-selections
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
fi

# Existing native Zeek takes precedence, including 9.x installations.
zeek_bin="${PCAP_ZEEK_BINARY:-}"
if [[ -z "$zeek_bin" ]]; then
  zeek_bin="$(command -v zeek || true)"
  [[ -n "$zeek_bin" ]] || zeek_bin=/opt/zeek/bin/zeek
fi
if ! "$zeek_bin" --version; then
  case "$VERSION_ID" in
    22.04|24.04|26.04) ;;
    *) echo "Install Zeek for Ubuntu $VERSION_ID, then rerun this script."; exit 1 ;;
  esac
  # Avoid mixing package release trains or repairing unknown package state.
  if dpkg-query -W -f='${db:Status-Status}\n' 'zeek*' 2>/dev/null |
      grep -Eq '^(installed|unpacked|half-configured|half-installed)$'; then
    echo "Zeek packages exist but the binary does not run. Set PCAP_ZEEK_BINARY or repair that installation first."
    exit 1
  fi
  sudo apt-get install -y gnupg ca-certificates
  repo="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${VERSION_ID}"
  curl -fsSL "$repo/Release.key" | gpg --dearmor |
    sudo tee /usr/share/keyrings/netflow-zeek.gpg >/dev/null
  echo "deb [signed-by=/usr/share/keyrings/netflow-zeek.gpg] $repo/ /" |
    sudo tee /etc/apt/sources.list.d/netflow-zeek.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y zeek
  zeek_bin=/opt/zeek/bin/zeek
  "$zeek_bin" --version
fi

dumpcap_bin="${PCAP_DUMPCAP_BINARY:-$(command -v dumpcap)}"
capture_caps="$(getcap "$dumpcap_bin" 2>/dev/null || true)"
if ! "$dumpcap_bin" -D >/dev/null 2>&1 ||
   { [[ ! -u "$dumpcap_bin" ]] && [[ "$capture_caps" != *cap_net_raw* ]]; }; then
  echo 'wireshark-common wireshark-common/install-setuid boolean true' | sudo debconf-set-selections
  sudo env DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common
fi
if getent group wireshark >/dev/null; then
  if ! id -nG "$(id -un)" | tr ' ' '\n' | grep -qx wireshark; then
    sudo usermod -aG wireshark "$(id -un)"
  fi
fi

if [[ -d .git && $(git branch --show-current) == main ]]; then
  if [[ -z $(git status --porcelain) ]]; then
    git pull --ff-only origin main
  else
    echo "Local edits found; running this checkout without pulling."
  fi
fi
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export PCAP_ZEEK_RUNTIME=native PCAP_ZEEK_BINARY="$zeek_bin" PCAP_DUMPCAP_BINARY="$dumpcap_bin"

# Verify the port before starting the browser helper.
.venv/bin/python -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",8000)); s.close()'
opener_pid=''
cleanup() {
  [[ -z "$opener_pid" ]] || kill "$opener_pid" 2>/dev/null || true
}
trap cleanup EXIT
(
  for attempt in {1..60}; do
    if curl --max-time 1 -fsS http://127.0.0.1:8000/ >/dev/null 2>&1; then
      xdg-open http://127.0.0.1:8000 >/dev/null 2>&1 || echo "Open http://127.0.0.1:8000 in your browser."
      exit 0
    fi
    sleep 1
  done
) &
opener_pid=$!
echo "Starting http://127.0.0.1:8000 (Ctrl+C stops the server)."
if getent group wireshark >/dev/null; then
  sg wireshark -c '"$PCAP_DUMPCAP_BINARY" -D && exec .venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000'
else
  "$dumpcap_bin" -D
  .venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000
fi
