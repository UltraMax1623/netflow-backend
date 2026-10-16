"""Explicit runtime settings; importing the package performs no analysis."""

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class AnalysisConfig:
    zeek_binary: str = "zeek"
    runtime: str = "native"  # "wsl" explicitly selects a configured WSL installation
    wsl_distribution: str | None = None
    timeout_seconds: float = 600
    ignore_checksums: bool = False
    correlation_window_seconds: float = 300
    dns_max_age_seconds: float = 300
    large_transfer_bytes: int = 50 * 1024 * 1024
    streaming_min_duration_seconds: float = 30
    max_graph_activities: int = 100

    def __post_init__(self):
        if self.runtime not in {"native", "wsl"}:
            raise ValueError("runtime must be 'native' or 'wsl'")
        if not self.zeek_binary:
            raise ValueError("zeek_binary must not be empty")
        for name in ("timeout_seconds", "correlation_window_seconds",
                     "dns_max_age_seconds", "streaming_min_duration_seconds"):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        for name in ("large_transfer_bytes", "max_graph_activities"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
