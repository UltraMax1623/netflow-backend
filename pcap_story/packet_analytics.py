"""Capture-wide counters and conservative, explainable security indicators.

No network lookups. Rates use capture time, not processing time. These rules
identify investigation leads, never an authenticated attack verdict.
"""
from collections import Counter, defaultdict
from .traffic_signals import TrafficSignals
from contextlib import contextmanager
import ipaddress
import math
import re
import socket
from struct import error as struct_error

import dpkt
from pydantic import BaseModel, Field, field_validator


class SecuritySettings(BaseModel):
    scan_ports: int = Field(default=20, ge=5, le=1000)
    sweep_hosts: int = Field(default=20, ge=5, le=1000)
    reset_min: int = Field(default=50, ge=5, le=1000000)
    dns_min_replies: int = Field(default=30, ge=10, le=1000000)
    dns_queries_minute: int = Field(default=300, ge=10, le=1000000)
    dns_long_names: int = Field(default=20, ge=5, le=1000)
    outbound_mb: float = Field(default=100, ge=1, le=1000000, allow_inf_nan=False)
    periodic_min: int = Field(default=10, ge=8, le=64)
    pps_threshold: float = Field(default=10000, ge=1, le=1e9, allow_inf_nan=False)
    icmp_pps_threshold: float = Field(default=1000, ge=1, le=1e9, allow_inf_nan=False)
    syn_min: int = Field(default=100, ge=10, le=1000000)
    completion_threshold: float = Field(default=20, ge=0, le=100, allow_inf_nan=False)
    ssh_attempts: int = Field(default=30, ge=5, le=1000000)
    baseline_pps: float | None = Field(default=None, gt=0, le=1e9, allow_inf_nan=False)
    gateway_ip: str = Field(default="", max_length=45)
    gateway_mac: str = Field(default="", max_length=17)

    @field_validator("gateway_ip")
    @classmethod
    def valid_gateway_ip(cls, value):
        if value:
            return str(ipaddress.IPv4Address(value))
        return value

    @field_validator("gateway_mac")
    @classmethod
    def valid_gateway_mac(cls, value):
        if value and not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
            raise ValueError("Expected a colon-separated MAC address.")
        return value.lower()


@contextmanager
def packets(path):
    with open(path, "rb") as handle:
        magic = handle.read(4)
        handle.seek(0)
        reader = dpkt.pcapng.Reader(handle) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(handle)
        yield reader


def decode(frame, linktype):
    if linktype == 1:
        ethernet = dpkt.ethernet.Ethernet(frame)
        return ethernet.data, ethernet.dst == b"\xff" * 6
    if linktype == 113:
        return dpkt.sll.SLL(frame).data, False
    if linktype == 276:  # Linux cooked capture v2
        if len(frame) < 20:
            raise dpkt.NeedData()
        protocol = int.from_bytes(frame[:2], "big")
        return (dpkt.ip.IP(frame[20:]) if protocol == 0x800 else
                dpkt.ip6.IP6(frame[20:]) if protocol == 0x86dd else frame[20:]), False
    if linktype in {0, 108}:  # loopback family header
        frame = frame[4:]
    if linktype in {0, 108, 12, 101, 228, 229}:
        return (dpkt.ip6.IP6(frame) if frame[0] >> 4 == 6 else dpkt.ip.IP(frame)), False
    return None, False


def dns_answer(record):
    """Compare decoded answers rather than packet-specific DNS compression offsets."""
    fields = {1: "ip", 28: "ip6", 5: "cname", 2: "nsname", 12: "ptrname"}
    value = getattr(record, fields.get(record.type, ""), record.rdata)
    if isinstance(value, bytes):
        value = value.hex()
    elif isinstance(value, str):
        value = value.lower().rstrip(".")
    return record.name.lower().rstrip("."), record.type, str(value)


def analyze_packets(path, settings=None):
    settings = settings or SecuritySettings()
    signals = TrafficSignals(settings)
    protocol_counts, services, sources, destinations, sizes = (Counter() for _ in range(5))
    start, end, count, byte_count = None, None, 0, 0
    # First pass determines a fixed-size timeline even for long captures.
    with packets(path) as reader:
        linktype = reader.datalink()
        for ts, frame in reader:
            ts = float(ts)
            if not math.isfinite(ts):
                raise ValueError("Capture contains a non-finite timestamp.")
            start = ts if start is None else min(start, ts)
            end = ts if end is None else max(end, ts)
            count += 1
            byte_count += len(frame)
    duration = (end - start) if count else 0
    bin_width = max(1.0, math.ceil(duration / 120))
    timeline = [{"time": (start or 0) + i * bin_width, "packets": 0, "bytes": 0, "syn": 0, "icmp": 0}
                for i in range(min(121, int(duration / bin_width) + 1))]
    arp_map, syns, dns_queries = {}, {}, {}
    syn_dest, ssh_dest = defaultdict(set), defaultdict(set)
    ssh_sources = defaultdict(set)
    findings, warnings, finding_keys = [], [], set()
    malformed = unsupported = fragments = 0
    syn_packets = synack_packets = resets = completed = 0
    dns_responses = http_requests = 0
    state_limit = 100000
    limited = False
    findings_limited = False

    def finding(key, severity, title, evidence, explanation):
        nonlocal findings_limited
        if key in finding_keys:
            return
        if len(findings) >= 100:
            findings_limited = True
            return
        finding_keys.add(key)
        findings.append({"severity": severity, "title": title, "evidence": evidence,
                         "explanation": explanation})

    def remember(mapping, key, value):
        nonlocal limited
        if key in mapping or len(mapping) < state_limit:
            mapping[key] = value
            return True
        limited = True
        return False

    with packets(path) as reader:
        for ts, frame in reader:
            ts = float(ts)
            bucket = timeline[min(len(timeline) - 1, max(0, int((ts - start) / bin_width)))]
            bucket["packets"] += 1
            bucket["bytes"] += len(frame)
            sizes["≤64" if len(frame) <= 64 else "65–128" if len(frame) <= 128 else
                  "129–512" if len(frame) <= 512 else "513–1024" if len(frame) <= 1024 else
                  "1025–1518" if len(frame) <= 1518 else ">1518"] += 1
            try:
                packet, broadcast = decode(frame, linktype)
                if broadcast:
                    services["Broadcast"] += 1
                if packet is None:
                    unsupported += 1
                    protocol_counts["Unsupported link"] += 1
                    continue
                if isinstance(packet, dpkt.arp.ARP):
                    protocol_counts["ARP"] += 1
                    if packet.pln == 4 and packet.hln == 6 and packet.op in (1, 2):
                        ip = socket.inet_ntoa(packet.spa)
                        mac = ":".join(f"{part:02x}" for part in packet.sha)
                        if ip != "0.0.0.0" and packet.sha != b"\x00" * 6:
                            previous = arp_map.get(ip)
                            if previous and previous != mac:
                                finding(("arp", ip), "warning", "Conflicting ARP mapping",
                                        {"ip": ip, "previous_mac": previous, "new_mac": mac, "time": ts},
                                        "Possible ARP spoofing; legitimate failover or address reassignment can also change a MAC.")
                            remember(arp_map, ip, mac)
                            if settings.gateway_ip == ip and settings.gateway_mac and mac != settings.gateway_mac.lower():
                                finding(("gateway", ip), "high", "Gateway MAC differs from configured baseline",
                                        {"ip": ip, "expected_mac": settings.gateway_mac, "observed_mac": mac},
                                        "Investigate a possible interception or legitimate gateway replacement.")
                    continue
                if not isinstance(packet, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    protocol_counts["Other"] += 1
                    continue
                src, dst = str(ipaddress.ip_address(packet.src)), str(ipaddress.ip_address(packet.dst))
                if isinstance(packet, dpkt.ip6.IP6):
                    services["IPv6"] += 1
                sources[src] += 1
                destinations[dst] += 1
                payload = packet.data
                signals.packet(ts, src, dst, payload, len(frame))
                if isinstance(packet, dpkt.ip.IP) and (packet.offset or packet.mf):
                    fragments += 1
                    protocol_counts["IP fragment"] += 1
                    continue
                if isinstance(payload, dpkt.tcp.TCP):
                    protocol_counts["TCP"] += 1
                    key = (src, payload.sport, dst, payload.dport, payload.seq)
                    flow_key = key[:4]
                    reverse = (dst, payload.dport, src, payload.sport)
                    flags = payload.flags
                    if flags & dpkt.tcp.TH_RST:
                        resets += 1
                    if flags & dpkt.tcp.TH_SYN and not flags & dpkt.tcp.TH_ACK:
                        syn_packets += 1
                        bucket["syn"] += 1
                        if key not in syns and remember(syns, key, {"ack": None, "completed": False}):
                            signals.syn(ts, src, dst, payload.dport)
                            syn_dest[dst].add(key)
                            if payload.dport == 22:
                                ssh_dest[dst].add(key)
                                ssh_sources[(src, dst)].add(key)
                    elif flags & dpkt.tcp.TH_SYN and flags & dpkt.tcp.TH_ACK:
                        synack_packets += 1
                        original = (*reverse, (payload.ack - 1) % 2**32)
                        if original in syns:
                            syns[original]["ack"] = (payload.seq + 1) % 2**32
                    elif flags & dpkt.tcp.TH_ACK:
                        original = (*flow_key, (payload.seq - 1) % 2**32)
                        state = syns.get(original)
                        if state and state["ack"] == payload.ack and not state["completed"]:
                            state["completed"] = True
                            completed += 1
                    if payload.dport == 22 or payload.sport == 22:
                        services["SSH port"] += 1
                    if payload.dport == 443 or payload.sport == 443:
                        services["TLS port"] += 1
                    if payload.data.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")):
                        try:
                            request = dpkt.http.Request(payload.data)
                            http_requests += 1
                            services["HTTP"] += 1
                            if 'authorization' in request.headers or 'proxy-authorization' in request.headers:
                                finding(('cleartext-auth', src, dst), 'high', 'Authorization header sent over plaintext HTTP',
                                        {'source': src, 'destination': dst, 'time': ts},
                                        'Authentication material is visible without TLS. Header contents are intentionally omitted; verify whether this is an approved test or proxy.')
                            referer = request.headers.get("referer", "")
                            if referer.lower().startswith("https://"):
                                finding(("http", src, dst), "warning", "Plaintext HTTP following an HTTPS referrer",
                                        {"source": src, "destination": dst, "host": request.headers.get("host"), "time": ts},
                                        "A downgrade investigation lead, not proof of TLS stripping; normal navigation can do this. Encrypted redirects are not visible.")
                        except (dpkt.UnpackError, ValueError):
                            pass
                elif isinstance(payload, dpkt.udp.UDP):
                    protocol_counts["UDP"] += 1
                    if {payload.sport, payload.dport} & {67, 68, 546, 547}:
                        services["DHCP port"] += 1
                    if payload.sport == 443 or payload.dport == 443:
                        services["UDP 443"] += 1
                    if payload.sport == 53 or payload.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(payload.data)
                            signals.dns_packet(ts, src, dst, dns)
                            services["DNS"] += 1
                            question = tuple((q.name.lower(), q.type, q.cls) for q in dns.qd)
                            if not question:
                                continue
                            client, port = (dst, payload.dport) if dns.qr else (src, payload.sport)
                            qkey = (client, port, dns.id, question)
                            if not dns.qr:
                                # A new query is a new transaction, even when an ID is reused.
                                remember(dns_queries, qkey, {"server": dst, "time": ts, "answers": None, "reply_time": None})
                            else:
                                dns_responses += 1
                                query = dns_queries.get(qkey)
                                if query and 0 <= ts - query["time"] <= 10:
                                    if src != query["server"]:
                                        finding(("dns-server", qkey), "warning", "DNS reply from an unexpected server",
                                                {"client": client, "query": question[0][0], "expected": query["server"], "actual": src},
                                                "Possible spoofing or resolver/network translation; verify against resolver configuration.")
                                    answer = tuple(sorted(dns_answer(rr) for rr in dns.an))
                                    if query["answers"] is not None and answer != query["answers"]:
                                        finding(("dns-answer", qkey), "warning", "Conflicting replies to one DNS transaction",
                                                {"client": client, "query": question[0][0], "server": src, "time": ts},
                                                "Different answer sets within 10 seconds of the same query. Retries and legitimate resolver behavior need review.")
                                    query["answers"], query["reply_time"] = answer, ts
                        except (dpkt.UnpackError, ValueError, IndexError):
                            pass
                elif isinstance(payload, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                    protocol_counts["ICMP"] += 1
                    bucket["icmp"] += 1
                else:
                    protocol_counts["Other IP"] += 1
            except (dpkt.UnpackError, ValueError, IndexError, struct_error):
                malformed += 1
                protocol_counts["Malformed"] += 1

    for bucket in timeline:
        # Rates for subsecond bins use at least one second to avoid enormous
        # apparent bursts from a handful of near-simultaneous packets.
        bucket["pps"] = bucket["packets"] / bin_width
        bucket["mbps"] = bucket["bytes"] * 8 / bin_width / 1e6
    peak = max((b["pps"] for b in timeline), default=0)
    threshold = max(settings.pps_threshold, (settings.baseline_pps or 0) * 3)
    if peak > threshold:
        finding("pps", "warning", "Packet-rate threshold exceeded",
                {"peak_bin_pps": peak, "threshold_pps": threshold, "unique_sources": len(sources), "bin_seconds": bin_width},
                "Possible traffic flood or a legitimate burst. Source count alone does not establish DDoS. A supplied baseline requires a 3× increase.")
    icmp_peak = max((b["icmp"] / bin_width for b in timeline), default=0)
    if icmp_peak > settings.icmp_pps_threshold:
        finding("icmp", "warning", "High ICMP packet rate",
                {"peak_bin_pps": icmp_peak, "threshold": settings.icmp_pps_threshold},
                "Possible ICMP flood; packet rate alone does not establish a ping-of-death attack.")
    for dst, keys in syn_dest.items():
        successes = sum(syns[key]["completed"] for key in keys)
        ratio = successes / len(keys) * 100
        if len(keys) >= settings.syn_min and ratio < settings.completion_threshold:
            finding(("syn", dst), "high", "Possible SYN flood / many incomplete TCP handshakes",
                    {"destination": dst, "unique_syn_attempts": len(keys), "completed": successes,
                     "completion_percent": round(ratio, 2), "unique_sources": len({key[0] for key in keys})},
                    "Completion = completed handshakes ÷ unique SYN attempts × 100. Capture loss, filtering, closed ports, and window boundaries can also lower this ratio.")
    for dst, keys in ssh_dest.items():
        if len(keys) >= settings.ssh_attempts:
            finding(("ssh", dst), "warning", "Repeated connection attempts to SSH port",
                    {"destination": dst, "attempts": len(keys), "unique_sources": len({key[0] for key in keys}),
                     "largest_single_source": max((len(v) for (s, d), v in ssh_sources.items() if d == dst), default=0)},
                    "Possible brute force or automated management. Encrypted SSH does not reveal failed passwords, usernames, or a later successful login; verify server authentication logs.")
    signals.finish(finding, resets, protocol_counts['TCP'])
    if signals.limited:
        warnings.append('Extended analysis reached its 20,000-entry limit per table; charts and indicators may be incomplete.')
    if unsupported:
        warnings.append(f"{unsupported} frames have an unsupported link type ({linktype}); protocol/security coverage is incomplete.")
    if malformed:
        warnings.append(f"{malformed} malformed/truncated frames could not be decoded.")
    if fragments:
        warnings.append(f"{fragments} IPv4 fragments were counted without transport reassembly.")
    if limited:
        warnings.append("Security state limit reached; only the first 100,000 tracked entries per detector are assessed.")
    if findings_limited:
        warnings.append("Only the first 100 distinct security findings are shown.")
    status = "high" if any(f["severity"] == "high" for f in findings) else "warning" if findings or warnings else "clear" if count else "unknown"
    return {
        **signals.charts(),
        "summary": {"total_packets": count, "total_bytes": byte_count, "duration": duration,
                    "start_time": start, "end_time": end, "average_pps": count / duration if duration > 0 else None,
                    "peak_pps": peak, "unique_sources": len(sources), "unique_destinations": len(destinations),
                    "malformed_packets": malformed, "linktype": linktype},
        "protocols": dict(protocol_counts), "services": dict(services),
        "top_sources": dict(sources.most_common(30)), "top_destinations": dict(destinations.most_common(30)),
        "packet_sizes": {label: sizes[label] for label in ("≤64", "65–128", "129–512", "513–1024", "1025–1518", ">1518")},
        "timeline": timeline, "bin_seconds": bin_width,
        "tcp": {"syn_packets": syn_packets, "syn_ack_packets": synack_packets, "unique_syn_attempts": len(syns),
                "completed_handshakes": completed, "resets": resets,
                "completion_percent": completed / len(syns) * 100 if syns else None},
        "security": {"status": status, "findings": findings, "warnings": warnings, "thresholds": settings.model_dump(),
                     "coverage": [
                         "Scans and DNS bursts use fixed 60-second intervals; boundaries may split a burst. Transfer volume covers this capture only. Periodicity samples the first 64 unique TCP attempts.",
                         "Long DNS names, NXDOMAIN errors, resets and periodic connections are investigation leads, not malware attribution. No external reputation API is configured.",
                         "Heuristics flag investigation leads; green means no configured indicators found, not proof of safety.",
                         "Rates are capture-wide; thresholds are configurable, not a learned network baseline.",
                         "ARP requires local-link frames. Gateway comparison requires a known IP/MAC baseline.",
                         "DNS checks cover visible UDP queries/replies within 10 seconds; encrypted DNS and TCP reassembly are not assessed. TTL changes alone are not flagged.",
                         "TLS stripping cannot be confirmed from encrypted traffic. Only complete plaintext HTTP requests with HTTPS referrers are flagged.",
                         "SSH connection bursts are observable; failed authentication and subsequent success need server logs.",
                         "Missing packets, one-way traffic, fragments and window boundaries reduce detection coverage."
                     ]},
    }


