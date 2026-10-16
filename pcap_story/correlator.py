"""Correlate by UID and by client-scoped, time-limited DNS answers."""

from bisect import bisect_right
from collections import defaultdict
import ipaddress

from .models import ActivityGroup, domain_matches


def _service_key(domains, fallback):
    if any(domain_matches(domain, suffix) for domain in domains
           for suffix in ("youtube.com", "googlevideo.com", "ytimg.com")):
        return "service:youtube"
    return "domain:" + sorted(domains)[0] if domains else "ip:" + fallback


def correlate(flows, events, config):
    by_uid, dns_index = defaultdict(list), defaultdict(list)
    for event in events:
        if event.uid:
            by_uid[event.uid].append(event)
        if event.type != "DNS_QUERY" or not event.data["domain"]:
            continue
        if event.data.get("rcode_name") not in (None, "NOERROR"):
            continue
        answers = event.data.get("answers") or []
        ttls = event.data.get("TTLs") or []
        if not isinstance(answers, list) or not isinstance(ttls, list):
            raise ValueError("DNS answers and TTLs must be arrays")
        for index, answer in enumerate(answers):
            try:
                address = str(ipaddress.ip_address(answer))
            except ValueError:
                continue  # CNAMEs are not destination addresses.
            age = config.dns_max_age_seconds
            if index < len(ttls) and ttls[index] is not None:
                from .flow_builder import number
                age = min(age, number(ttls[index]))
            dns_index[(event.source["ip"], address)].append(
                (event.timestamp, event.timestamp + age, event)
            )
    # Events arrive chronologically; retain lookup arrays to avoid rescanning all DNS.
    dns_times = {key: [item[0] for item in records] for key, records in dns_index.items()}
    groups, active, assigned = [], {}, set()
    for flow in flows:
        related = [event for event in by_uid[flow.uid]
                   if event.source["ip"] == flow.source_ip
                   and event.destination["ip"] == flow.destination_ip]
        # A DNS connection's question is about another server, not its resolver.
        domains = {event.data["domain"] for event in related
                   if event.type in {"TLS_CONNECTION", "HTTP_REQUEST"} and event.data.get("domain")}
        key = (flow.source_ip, flow.destination_ip)
        records = dns_index.get(key, [])
        stop = bisect_right(dns_times.get(key, []), flow.start)
        for record_index in range(stop - 1, -1, -1):
            timestamp, expiry, event = records[record_index]
            if flow.start - timestamp > config.dns_max_age_seconds:
                break
            if expiry <= flow.start:
                continue
            # SNI/HTTP identifies this connection more directly than a shared-IP DNS answer.
            if domains and event.data["domain"] not in domains:
                continue
            related.append(event)
            domains.add(event.data["domain"])
        service = _service_key(domains, flow.destination_ip)
        group_key = (flow.source_ip, service)
        group = active.get(group_key)
        if group is None or flow.start - group.end > config.correlation_window_seconds:
            group = ActivityGroup(flow.source_ip, service, flow.start, flow.end)
            active[group_key] = group
            groups.append(group)
        group.flows.append(flow)
        group.end = max(group.end, flow.end)
        group.start = min(group.start, *(event.timestamp for event in related)) if related else group.start
        group.domains.update(domains)
        known = {event.id for event in group.events}
        for event in related:
            assigned.add(event.id)
            if event.id not in known:
                group.events.append(event)
                known.add(event.id)
    # Retain standalone DNS observations even if their connection summary is absent.
    for event in events:
        if event.id not in assigned and event.type == "DNS_QUERY":
            groups.append(ActivityGroup(
                event.source["ip"], "dns", event.timestamp, event.timestamp,
                events=[event], domains={event.data["domain"]} if event.data.get("domain") else set(),
            ))
    return groups
