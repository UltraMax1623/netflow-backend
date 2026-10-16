"""Zeek subprocess boundary: isolated logs, no shell, explicit timeout."""

from contextlib import contextmanager
from pathlib import Path
import subprocess
import tempfile

from .config import AnalysisConfig


class ZeekError(RuntimeError):
    """Zeek could not complete analysis; this is never an empty success."""


def _wsl_prefix(config):
    prefix = ["wsl.exe"]
    if config.wsl_distribution:
        prefix += ["--distribution", config.wsl_distribution]
    return prefix


def _wsl_path(path: Path, config: AnalysisConfig) -> str:
    try:
        result = subprocess.run(
            _wsl_prefix(config) + ["--exec", "wslpath", "-a", str(path)],
            capture_output=True, text=True, timeout=30, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ZeekError("Cannot translate paths through WSL. Configure WSL and Zeek first.") from exc
    translated = result.stdout.strip()
    if not translated.startswith("/"):
        raise ZeekError("WSL returned an invalid filesystem path")
    return translated


@contextmanager
def run_zeek(pcap_path: Path, config: AnalysisConfig):
    with tempfile.TemporaryDirectory(prefix="pcap_story_") as temporary:
        log_dir = Path(temporary)
        capture = str(pcap_path)
        prefix = []
        if config.runtime == "wsl":
            capture = _wsl_path(pcap_path, config)
            prefix = _wsl_prefix(config) + ["--cd", _wsl_path(log_dir, config), "--exec"]
        command = prefix + [config.zeek_binary]
        if config.ignore_checksums:
            command.append("-C")
        command += ["-r", capture, "LogAscii::use_json=T"]
        try:
            result = subprocess.run(
                command, cwd=log_dir, capture_output=True, text=True,
                errors="replace", timeout=config.timeout_seconds, check=False,
            )
        except FileNotFoundError as exc:
            raise ZeekError(
                "Zeek runtime not found. Install Zeek and add it to PATH, set "
                "AnalysisConfig(zeek_binary=...), or configure runtime='wsl'."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ZeekError(f"Zeek exceeded {config.timeout_seconds:g} seconds") from exc
        except OSError as exc:
            raise ZeekError(f"Unable to start Zeek: {exc}") from exc
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()[-2000:]
            raise ZeekError(f"Zeek exited with code {result.returncode}: {detail}")
        diagnostics = [line.strip() for line in result.stderr.splitlines() if line.strip()]
        yield log_dir, diagnostics
