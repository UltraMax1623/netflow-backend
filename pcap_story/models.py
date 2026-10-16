"""Normalized, tool-independent records. Timestamps are UNIX seconds (UTC)."""

from dataclasses import dataclass, field
import hashlib


def stable_id(kind: str, *parts: object) -> str:
    import json
    payload = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    return kind + "_" + hashlib.sha256(payload.encode()).hexdigest()[:20]


@dataclass
class Flow:
    id: str
    uid: str
    start: float
    end: float
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    service: str | None
    bytes_sent: int | None
    bytes_received: int | None
    packets_sent: int | None
    packets_received: int | None
    state: str | None


@dataclass
class Event:
    id: str
    timestamp: float
    type: str
    uid: str | None
    source: dict
    destination: dict
    data: dict
    source_tool: str = "zeek"


@dataclass
class ActivityGroup:
    host: str
    key: str
    start: float
    end: float
    flows: list[Flow] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    domains: set[str] = field(default_factory=set)


def normalize_domain(value: object) -> str | None:
    """Normalize DNS names without treating substring matches as service evidence."""
    if not isinstance(value, str):
        return None
    name = value.strip().rstrip(".").lower()
    if not name or any(c.isspace() for c in name) or "/" in name:
        return None
    # HTTP Host can contain a port. Bracketed IPv6 is not a domain.
    if name.count(":") == 1:
        name, port = name.rsplit(":", 1)
        if not port.isdigit():
            return None
    elif ":" in name:
        return None
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def domain_matches(name: str, suffix: str) -> bool:
    return name == suffix or name.endswith("." + suffix)
