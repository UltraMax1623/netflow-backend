import io
import socket
import tempfile
import unittest
from pathlib import Path

import dpkt

from pcap_story.packet_analytics import SecuritySettings, analyze_packets


def frame(payload, src="10.0.0.1", dst="10.0.0.2"):
    protocol = 6 if isinstance(payload, dpkt.tcp.TCP) else 17 if isinstance(payload, dpkt.udp.UDP) else 1
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=protocol, data=payload)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x01" * 6, dst=b"\x02" * 6, type=0x800, data=ip))


def tcp(sport=1234, dport=443, flags=dpkt.tcp.TH_SYN, seq=100, ack=0, data=b""):
    return dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, data=data)


class PacketAnalyticsTests(unittest.TestCase):
    def analyze(self, frames, settings=None, ng=False, linktype=1):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / ("sample.pcapng" if ng else "sample.pcap")
            with path.open("wb") as output:
                writer = dpkt.pcapng.Writer(output, linktype=linktype) if ng else dpkt.pcap.Writer(output, linktype=linktype)
                for ts, packet in frames:
                    writer.writepkt(packet, ts=ts)
            return analyze_packets(path, settings)

    def test_real_counts_bins_and_formats(self):
        frames = [(100, frame(tcp())), (102, frame(dpkt.udp.UDP(sport=80, dport=81, data=b"test")))]
        for ng in (False, True):
            result = self.analyze(frames, ng=ng)
            self.assertEqual(result["summary"]["total_packets"], 2)
            self.assertEqual(result["summary"]["total_bytes"], sum(len(p) for _, p in frames))
            self.assertEqual(result["summary"]["average_pps"], 1)
            self.assertEqual(result["protocols"], {"TCP": 1, "UDP": 1})
            self.assertEqual(sum(b["packets"] for b in result["timeline"]), 2)
            self.assertEqual(result["security"]["status"], "clear")

    def test_complete_handshake_deduplicates_syn_retransmission(self):
        result = self.analyze([
            (1, frame(tcp())), (1.1, frame(tcp())),
            (1.2, frame(tcp(sport=443, dport=1234, flags=18, seq=500, ack=101), "10.0.0.2", "10.0.0.1")),
            (1.3, frame(tcp(flags=16, seq=101, ack=501))),
            (1.4, frame(tcp(flags=16, seq=101, ack=501))),
        ])
        self.assertEqual(result["tcp"]["syn_packets"], 2)
        self.assertEqual(result["tcp"]["unique_syn_attempts"], 1)
        self.assertEqual(result["tcp"]["completed_handshakes"], 1)
        self.assertEqual(result["tcp"]["completion_percent"], 100)

    def test_syn_flood_and_ssh_indicators_are_evidence_based(self):
        result = self.analyze([(i / 10, frame(tcp(sport=1000 + i, dport=22))) for i in range(40)],
                              SecuritySettings(syn_min=10, ssh_attempts=30))
        titles = [f["title"] for f in result["security"]["findings"]]
        self.assertTrue(any("SYN" in title for title in titles))
        self.assertTrue(any("SSH" in title for title in titles))
        self.assertEqual(result["security"]["status"], "high")
        self.assertEqual(result["tcp"]["completion_percent"], 0)

    def test_rate_baseline_and_zero_duration(self):
        frames = [(1, frame(tcp(sport=1000+i))) for i in range(20)]
        result = self.analyze(frames, SecuritySettings(pps_threshold=10))
        self.assertIsNone(result["summary"]["average_pps"])
        self.assertEqual(result["summary"]["peak_pps"], 20)
        self.assertTrue(result["security"]["findings"])
        result = self.analyze(frames, SecuritySettings(pps_threshold=10, baseline_pps=100))
        self.assertFalse(result["security"]["findings"])

    def test_arp_changes_and_gateway_baseline(self):
        def arp(mac):
            return bytes(dpkt.ethernet.Ethernet(type=0x806, data=dpkt.arp.ARP(
                op=2, spa=socket.inet_aton("10.0.0.1"), sha=mac,
                tpa=socket.inet_aton("10.0.0.2"), tha=b"\x02"*6)))
        result = self.analyze([(1, arp(b"\x01"*6)), (2, arp(b"\x03"*6))],
                              SecuritySettings(gateway_ip="10.0.0.1", gateway_mac="01:01:01:01:01:01"))
        self.assertEqual(len(result["security"]["findings"]), 2)
        self.assertEqual(result["security"]["status"], "high")
        self.assertEqual(result["protocols"]["ARP"], 2)

    def test_dns_conflicts_but_not_identical_duplicate_or_ttl(self):
        query = dpkt.dns.DNS(id=123, qd=[dpkt.dns.DNS.Q(name="example.com")])
        def response(address, ttl=100):
            return dpkt.dns.DNS(id=123, qr=1, qd=query.qd, an=[
                dpkt.dns.DNS.RR(name="example.com", type=1, ttl=ttl, rdata=socket.inet_aton(address))])
        frames = [(1, frame(dpkt.udp.UDP(sport=1000, dport=53, data=bytes(query))))]
        for ts, answer in [(2, response("1.1.1.1")), (3, response("1.1.1.1", 50))]:
            frames.append((ts, frame(dpkt.udp.UDP(sport=53, dport=1000, data=bytes(answer)), "10.0.0.2", "10.0.0.1")))
        self.assertFalse(self.analyze(frames)["security"]["findings"])
        frames.append((4, frame(dpkt.udp.UDP(sport=53, dport=1000, data=bytes(response("2.2.2.2"))),
                                "10.0.0.3", "10.0.0.1")))
        result = self.analyze(frames)
        self.assertEqual(len(result["security"]["findings"]), 2)

    def test_http_referrer_lead_not_claim_of_attack(self):
        request = b"GET / HTTP/1.1\r\nHost: example.com\r\nReferer: https://example.com/\r\n\r\n"
        result = self.analyze([(1, frame(tcp(dport=80, flags=16, data=request)))])
        self.assertEqual(result["services"]["HTTP"], 1)
        self.assertIn("not proof", result["security"]["findings"][0]["explanation"])

    def test_empty_malformed_and_unsupported_are_not_green(self):
        self.assertEqual(self.analyze([])["security"]["status"], "unknown")
        self.assertEqual(self.analyze([(1, b"x")])["summary"]["malformed_packets"], 1)
        unsupported = self.analyze([(1, b"x")], linktype=999)
        self.assertEqual(unsupported["security"]["status"], "warning")
        self.assertEqual(unsupported["protocols"]["Unsupported link"], 1)

    def test_raw_ip_and_long_capture_bounded_timeline(self):
        raw = bytes(dpkt.ethernet.Ethernet(frame(tcp())).data)
        result = self.analyze([(1, raw), (100000, raw)], linktype=101)
        self.assertEqual(result["protocols"]["TCP"], 2)
        self.assertLessEqual(len(result["timeline"]), 121)

    def test_settings_validation(self):
        for settings in [{"gateway_ip": "bad"}, {"gateway_mac": "bad"}, {"pps_threshold": float("nan")}]:
            with self.assertRaises(ValueError):
                SecuritySettings(**settings)
