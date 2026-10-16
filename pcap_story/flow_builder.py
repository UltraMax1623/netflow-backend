"""Normalize Zeek connection summaries without recounting protocol-log traffic."""

import ipaddress
import math
from .models import Flow, stable_id


def number(value, default=None):
    if value is None:
        return default
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"Expected a finite, nonnegative number: {value!r}")
    return result


def integer(value):
    result = number(value)
    if result is None:
        return None
    if not result.is_integer():
        raise ValueError(f"Expected an integer: {value!r}")
    return int(result)


def endpoint(record, side):
    address = str(ipaddress.ip_address(record[f"id.{side}_h"]))
    port = integer(record.get(f"id.{side}_p"))
    if port is not None and port > 65535:
        raise ValueError("Port exceeds 65535")
    return {"ip": address, "port": port}


def build_flows(records):
    flows, seen = [], set()
    for record in records:
        uid = record["uid"]
        if not isinstance(uid, str) or not uid or uid in seen:
            raise ValueError(f"Missing or duplicate connection UID: {uid!r}")
        seen.add(uid)
        start = number(record["ts"])
        if start is None:
            raise ValueError("Connection timestamp is required")
        source, destination = endpoint(record, "orig"), endpoint(record, "resp")
        end = number(start + number(record.get("duration"), 0))
        flows.append(Flow(
            id=stable_id("flow", uid), uid=uid, start=start,
            end=end,
            source_ip=source["ip"], destination_ip=destination["ip"],
            source_port=source["port"], destination_port=destination["port"],
            protocol=str(record.get("proto", "unknown")), service=record.get("service"),
            bytes_sent=integer(record.get("orig_bytes")),
            bytes_received=integer(record.get("resp_bytes")),
            packets_sent=integer(record.get("orig_pkts")),
            packets_received=integer(record.get("resp_pkts")), state=record.get("conn_state"),
        ))
    return sorted(flows, key=lambda flow: (flow.start, flow.id))
