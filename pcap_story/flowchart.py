"""Public orchestration API. Existing application routes need not be imported."""

from pathlib import Path
from dataclasses import asdict

from .config import AnalysisConfig
from .correlator import correlate
from .detector import detect_activities
from .event_extractor import extract_events
from .flow_builder import build_flows
from .graph_builder import build_graph
from .story_generator import generate_story
from .zeek_parser import parse_zeek_logs
from .zeek_runner import run_zeek

MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}


def _validate_capture(pcap_path):
    path = Path(pcap_path).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"Capture path is not a file: {path}")
    if path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise ValueError("Expected a .pcap, .pcapng, or .cap capture")
    with path.open("rb") as handle:
        if handle.read(4) not in MAGIC:
            raise ValueError("File does not have a supported PCAP/PCAPNG header")
    return path


def _analyze_logs(directory, config, capture_name, warnings=()):
    """Shared pipeline, also usable for fixture-based verification."""
    logs = parse_zeek_logs(Path(directory))
    flows = build_flows(logs["conn"])
    events = extract_events(logs, flows)
    activities = generate_story(detect_activities(correlate(flows, events, config), config))
    nodes, edges = build_graph(activities, flows, config)
    notes = list(warnings)
    if not flows:
        notes.append("No connection records were produced; capture may be empty or traffic unsupported.")
    notes.append("Packet and byte metrics are Zeek connection metrics, not whole-capture totals.")
    if len(activities) > config.max_graph_activities:
        notes.append("Graph activity limit reached; the activities list retains the complete story.")
    starts = [event.timestamp for event in events] + [flow.start for flow in flows]
    ends = [event.timestamp for event in events] + [flow.end for flow in flows]

    def total(field):
        values = [getattr(flow, field) for flow in flows]
        return sum(values) if values and all(value is not None for value in values) else None

    sent_packets, received_packets = total("packets_sent"), total("packets_received")
    summary = {
        "schema_version": "1.1", "pcap": capture_name, "analysis_tool": "zeek",
        "start_time": min(starts) if starts else None, "end_time": max(ends) if ends else None,
        "duration": max(ends) - min(starts) if starts else 0,
        "packet_count": None,
        "connection_packet_count": sent_packets + received_packets
        if sent_packets is not None and received_packets is not None else None,
        "bytes_sent": total("bytes_sent"), "bytes_received": total("bytes_received"),
        "connection_count": len(flows), "event_count": len(events),
        "host_count": len({ip for flow in flows for ip in (flow.source_ip, flow.destination_ip)}
                          | {event.source["ip"] for event in events}
                          | {event.destination["ip"] for event in events}),
        "activity_count": len(activities),
        "graph_activity_count": min(len(activities), config.max_graph_activities),
        "graph_truncated": len(activities) > config.max_graph_activities,
        "time_basis": "UNIX seconds, UTC", "warnings": notes,
    }
    # Each connection appears once. Protocol observations, rather than DNS IP
    # coincidence, supply its domain. This supports honest UI aggregation.
    connection_domains = {}
    for event in events:
        if event.type in {"TLS_CONNECTION", "HTTP_REQUEST"} and event.data.get("domain"):
            connection_domains.setdefault(event.uid, set()).add(event.data["domain"])
    connections = []
    for flow in flows:
        domains = sorted(connection_domains.get(flow.uid, set()))
        connections.append({**asdict(flow), "domain": domains[0] if len(domains) == 1 else None,
                            "observed_domains": domains})
    return {"summary": summary, "activities": activities, "nodes": nodes, "edges": edges,
            "connections": connections}


def get_flowchart(pcap_path, *, config: AnalysisConfig | None = None) -> dict:
    """Analyze a local capture; return summary, activities, nodes, and edges.

    No JSON file is written and no network enrichment is performed. Each call
    uses independent temporary logs. ZeekError indicates unavailable/failed Zeek;
    ValueError indicates unsupported input or invalid log records.
    """
    path = _validate_capture(pcap_path)
    settings = config if config is not None else AnalysisConfig()
    with run_zeek(path, settings) as (logs, diagnostics):
        return _analyze_logs(logs, settings, path.name, diagnostics)
