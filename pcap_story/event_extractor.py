"""Produce observed protocol facts, keeping their original log provenance."""

from .flow_builder import endpoint, number
from .models import Event, normalize_domain, stable_id


def extract_events(logs, flows):
    events = []
    for flow in flows:
        events.append(Event(
            stable_id("event", "conn", flow.uid), flow.start, "CONNECTION", flow.uid,
            {"ip": flow.source_ip, "port": flow.source_port},
            {"ip": flow.destination_ip, "port": flow.destination_port},
            {"flow_id": flow.id, "protocol": flow.protocol, "service": flow.service,
             "end_time": flow.end, "bytes_sent": flow.bytes_sent,
             "bytes_received": flow.bytes_received, "log": "conn.log"},
        ))
    specifications = {
        "dns": ("DNS_QUERY", "query", ("answers", "TTLs", "qtype_name", "rcode_name")),
        "ssl": ("TLS_CONNECTION", "server_name", ("version", "cipher", "established")),
        "http": ("HTTP_REQUEST", "host", ("method", "uri", "status_code", "response_body_len")),
    }
    for log, (kind, domain_field, fields) in specifications.items():
        for index, record in enumerate(logs.get(log, [])):
            timestamp = number(record["ts"])
            if timestamp is None:
                raise ValueError(f"{log}.log event requires a timestamp")
            data = {name: record.get(name) for name in fields}
            data.update(domain=normalize_domain(record.get(domain_field)), log=f"{log}.log")
            events.append(Event(
                stable_id("event", log, index, record.get("uid"), timestamp),
                timestamp, kind, record.get("uid"),
                endpoint(record, "orig"), endpoint(record, "resp"), data,
            ))
    return sorted(events, key=lambda event: (event.timestamp, event.id))
