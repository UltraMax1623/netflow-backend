"""Transparent heuristics; confidence scores are rule strengths, not probabilities."""

from dataclasses import asdict
from .models import domain_matches, stable_id


def _sum_known(flows, field):
    values = [getattr(flow, field) for flow in flows]
    return sum(values) if values and all(value is not None for value in values) else None


def detect_activities(groups, config):
    activities = []
    for group in groups:
        sent = _sum_known(group.flows, "bytes_sent")
        received = _sum_known(group.flows, "bytes_received")
        duration = group.end - group.start
        kinds = {event.type for event in group.events}
        web = bool(kinds & {"TLS_CONNECTION", "HTTP_REQUEST"})
        video = any(domain_matches(domain, "googlevideo.com") for domain in group.domains)
        youtube = any(domain_matches(domain, "youtube.com") for domain in group.domains)
        if web and video and youtube and received is not None and (
            received >= config.large_transfer_bytes and duration >= config.streaming_min_duration_seconds
        ):
            kind, title, confidence = "possible_streaming", "Possible YouTube streaming", 0.85
            reason = "YouTube and video-delivery domains, encrypted/web traffic, and a large download over the activity interval"
        elif received is not None and received >= config.large_transfer_bytes and received > (sent or 0):
            kind, title, confidence = "large_download", "Large inbound transfer", 0.9
            reason = "Responder-to-originator bytes exceeded the configured transfer threshold"
        elif sent is not None and sent >= config.large_transfer_bytes:
            kind, title, confidence = "large_upload", "Large outbound transfer", 0.9
            reason = "Originator-to-responder bytes exceeded the configured transfer threshold"
        elif web:
            kind, title, confidence = "web_activity", "Observed web/TLS activity", 0.8
            reason = "Captured TLS or HTTP protocol evidence"
        elif "DNS_QUERY" in kinds and (not group.flows or all(
            flow.destination_port == 53 for flow in group.flows
        )):
            kind, title, confidence = "dns_activity", "Observed DNS activity", 1.0
            reason = "Captured DNS queries; queries alone do not establish a website visit"
        else:
            kind, title, confidence = "network_connection", "Observed network communication", 1.0
            reason = "Captured connection summaries"
        evidence = []
        for event in sorted(group.events, key=lambda item: (item.timestamp, item.id)):
            evidence.append(asdict(event))
        statistics = {
            "bytes_sent": sent, "bytes_received": received,
            "packets_sent": _sum_known(group.flows, "packets_sent"),
            "packets_received": _sum_known(group.flows, "packets_received"),
            "connection_count": len(group.flows),
        }
        activities.append({
            "id": stable_id("activity", group.host, group.key, [flow.id for flow in group.flows],
                            [event.id for event in group.events]),
            "type": kind, "title": title, "start_time": group.start, "end_time": group.end,
            "confidence": confidence, "confidence_basis": "heuristic rule strength; not a calibrated probability",
            "reason": reason, "source_ip": group.host, "domains": sorted(group.domains),
            "destination_ips": sorted({flow.destination_ip for flow in group.flows}),
            "statistics": statistics, "flow_ids": [flow.id for flow in group.flows],
            "evidence": evidence,
        })
    return activities
