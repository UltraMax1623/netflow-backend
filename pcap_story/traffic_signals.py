"""Bounded capture evidence. No reputation lookup, decryption or attack prediction."""
from collections import Counter
import ipaddress
import math
import statistics


class TrafficSignals:
    def __init__(self, settings):
        self.settings = settings
        self.tables = {}
        self.limited = False
        self.direction = Counter()
        self.dns = Counter()

    def entry(self, table, key, factory):
        mapping = self.tables.setdefault(table, {})
        if key not in mapping:
            if len(mapping) >= 20000:
                self.limited = True
                return None
            mapping[key] = factory()
        return mapping[key]

    def count(self, table, key, amount=1):
        if self.entry(table, key, lambda: 0) is not None:
            self.tables[table][key] += amount

    def packet(self, ts, src, dst, payload, size):
        source, target = ipaddress.ip_address(src), ipaddress.ip_address(dst)
        # RFC1918 / ULA rather than is_private (which includes reserved space).
        def local(ip):
            return any(ip in net for net in LOCAL_NETS if net.version == ip.version)
        direction = ('Private → public' if local(source) and target.is_global else
                     'Public → private' if source.is_global and local(target) else 'Other / local')
        self.direction[direction] += size
        if direction == 'Private → public':
            self.count('outbound', (src, dst), size)
        if hasattr(payload, 'dport'):
            self.count('ports', str(payload.dport))
        self.count('conversations', (src, dst), size)

    def syn(self, ts, src, dst, port):
        window = math.floor(ts / 60)
        for table, key, value, maximum in [
            ('scan', (src, dst, window), port, self.settings.scan_ports),
            ('sweep', (src, port, window), dst, self.settings.sweep_hosts),
        ]:
            values = self.entry(table, key, set)
            if values is not None and len(values) < maximum:
                values.add(value)
        times = self.entry('periodic', (src, dst, port), list)
        if times is not None and len(times) < 64:
            times.append(ts)

    def dns_packet(self, ts, src, dst, dns):
        if dns.qr:
            self.dns['Replies'] += 1
            if dns.rcode == 3:
                self.dns['NXDOMAIN'] += 1
            counts = self.entry('dns_fail', dst, Counter)
            if counts is not None:
                counts['replies'] += 1
                counts['failed'] += int(dns.rcode == 3)
        else:
            self.dns['Queries'] += 1
            self.count('dns_burst', (src, math.floor(ts / 60)))
            for q in dns.qd:
                # Long names are only a lead when many distinct names occur.
                name = q.name.lower().rstrip('.')
                if len(name) >= 100 or max(map(len, name.split('.')), default=0) >= 50:
                    names = self.entry('long_dns', src, set)
                    if names is not None and len(names) < self.settings.dns_long_names:
                        names.add(name)

    def finish(self, finding, resets, tcp_packets):
        s = self.settings
        for (src, dst, window), ports in self.tables.get('scan', {}).items():
            if len(ports) >= s.scan_ports:
                finding(('scan', src, dst), 'warning', 'Possible TCP port scan',
                        {'source': src, 'destination': dst, 'distinct_ports_at_least': len(ports),
                         'threshold': s.scan_ports, 'window_start': window * 60, 'window_seconds': 60},
                        'Initial SYNs reach many ports in a fixed 60-second interval. Authorized scanners can do this too.')
        for (src, port, window), hosts in self.tables.get('sweep', {}).items():
            if len(hosts) >= s.sweep_hosts:
                finding(('sweep', src, port), 'warning', 'Possible TCP host sweep',
                        {'source': src, 'port': port, 'distinct_hosts_at_least': len(hosts),
                         'threshold': s.sweep_hosts, 'window_start': window * 60},
                        'Initial SYNs target many hosts on one port within a fixed 60-second interval. Discovery tools can be legitimate.')
        if resets >= s.reset_min and tcp_packets and resets / tcp_packets >= .2:
            finding('resets', 'warning', 'Elevated TCP reset share',
                    {'reset_packets': resets, 'tcp_packets': tcp_packets, 'percent': round(100 * resets / tcp_packets, 2),
                     'minimum_resets': s.reset_min, 'minimum_percent': 20},
                    'Resets can indicate rejected connections, scans or application failures; packet counts are not failed login counts.')
        for client, counts in self.tables.get('dns_fail', {}).items():
            if counts['replies'] >= s.dns_min_replies and counts['failed'] / counts['replies'] >= .5:
                finding(('nxdomain', client), 'warning', 'High DNS name-error share',
                        {'client': client, **counts, 'minimum_replies': s.dns_min_replies, 'minimum_percent': 50},
                        'At least half of visible DNS replies are NXDOMAIN. Check misspellings, resolver policy and possible generated-domain activity.')
        for (client, window), count in self.tables.get('dns_burst', {}).items():
            if count >= s.dns_queries_minute:
                finding(('dns-burst', client), 'warning', 'DNS query burst',
                        {'client': client, 'queries': count, 'window_start': window * 60, 'window_seconds': 60,
                         'threshold': s.dns_queries_minute},
                        'High query volume in a fixed minute may be automation, retries or abuse. This is not evidence of spoofing by itself.')
        for client, names in self.tables.get('long_dns', {}).items():
            if len(names) >= s.dns_long_names:
                finding(('long-dns', client), 'warning', 'Many unusually long DNS names',
                        {'client': client, 'distinct_names_at_least': len(names), 'threshold': s.dns_long_names},
                        'Possible DNS tunneling lead: names have at least 100 characters or a label of 50 characters. Tracking and security software also use long names.')
        for (src, dst), size in self.tables.get('outbound', {}).items():
            if size >= s.outbound_mb * 1000000:
                finding(('outbound', src, dst), 'warning', 'Large private-to-public transfer',
                        {'source': src, 'destination': dst, 'captured_bytes': size, 'threshold_MB': s.outbound_mb},
                        'Capture-wide frame bytes exceeded the configured limit. Backups and uploads are common; this does not establish data theft.')
        for (src, dst, port), times in self.tables.get('periodic', {}).items():
            if len(times) < s.periodic_min:
                continue
            intervals = [b - a for a, b in zip(sorted(times), sorted(times)[1:])]
            mean = statistics.mean(intervals)
            if mean >= 5 and statistics.pstdev(intervals) / mean <= .1:
                finding(('periodic', src, dst, port), 'warning', 'Regularly repeated TCP connections',
                        {'source': src, 'destination': dst, 'port': port, 'sample_attempts': len(times),
                         'mean_interval_seconds': round(mean, 2), 'minimum_attempts': s.periodic_min},
                        'First 64 unique SYN attempts have interval variation ≤10% and mean interval ≥5 seconds. Scheduled polling is common; beaconing requires further evidence.')

    def charts(self):
        def top(table):
            return sorted(self.tables.get(table, {}).items(), key=lambda item: item[1], reverse=True)[:30]
        return {'destination_ports': dict(top('ports')), 'direction_bytes': dict(self.direction),
                'dns_counts': dict(self.dns),
                'top_conversations': {f'{src} → {dst}': size for (src, dst), size in top('conversations')}}


LOCAL_NETS = tuple(map(ipaddress.ip_network, ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7')))
