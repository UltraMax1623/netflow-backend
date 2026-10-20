"""Bounded local adapter capture through Wireshark's dumpcap."""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading

from fastapi import HTTPException

_capture_lock = threading.Lock()
_phase = "idle"


def capture_status():
    return {"phase": _phase}


def dumpcap_binary():
    configured = os.getenv("PCAP_DUMPCAP_BINARY")
    if configured:
        return configured
    found = shutil.which("dumpcap")
    if found:
        return found
    windows_path = Path(os.getenv("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "dumpcap.exe"
    if windows_path.is_file():
        return str(windows_path)
    raise HTTPException(503, "Install Wireshark with Npcap (Windows) or dumpcap, "
                        "or set PCAP_DUMPCAP_BINARY to its executable path.")


def _run(arguments, timeout):
    try:
        result = subprocess.run(
            arguments, capture_output=True, text=True, errors="replace",
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(504, "Live capture timed out.") from exc
    except OSError as exc:
        raise HTTPException(503, "Cannot launch dumpcap. Check PCAP_DUMPCAP_BINARY.") from exc
    if result.returncode:
        raise HTTPException(502, "Capture failed. Check adapter permissions, Npcap, "
                            "and capture filter: " + (result.stderr or result.stdout)[-2000:])
    return result


def list_interfaces(binary=None):
    result = _run([binary or dumpcap_binary(), "-D"], 15)
    interfaces = []
    for line in result.stdout.splitlines():
        match = re.match(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?$", line.strip())
        if match:
            interfaces.append({"id": match[2], "label": match[3] or match[2]})
    return interfaces


@contextmanager
def capture_window(interface, seconds, capture_filter):
    global _phase
    if not _capture_lock.acquire(blocking=False):
        raise HTTPException(409, "Another live capture is already running.")
    try:
        _phase = "preparing"
        binary = dumpcap_binary()
        if interface not in {item["id"] for item in list_interfaces(binary)}:
            raise HTTPException(400, "Adapter is unavailable. Refresh the adapter list.")
        with tempfile.TemporaryDirectory(prefix="pcap_live_") as directory:
            path = Path(directory) / "live.pcap"
            command = [
                binary, "-i", interface, "-p", "-P", "-q",
                "-a", f"duration:{seconds}", "-a", "filesize:25000",
                "-c", "100000", "-w", str(path),
            ]
            if capture_filter:
                command += ["-f", capture_filter]
            _phase = "capturing"
            _run(command, seconds + 15)
            if not path.is_file():
                raise HTTPException(502, "Capture tool did not produce a capture file.")
            _phase = "analyzing"
            yield path
    finally:
        _phase = "idle"
        _capture_lock.release()
