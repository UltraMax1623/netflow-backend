"""Offline verification using representative Zeek records; no API credentials needed."""

from contextlib import contextmanager
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pcap_story import AnalysisConfig, ZeekError, get_flowchart
from pcap_story.flowchart import _analyze_logs
from pcap_story.flow_builder import build_flows
from pcap_story.models import domain_matches
from pcap_story.zeek_parser import read_log
from pcap_story.zeek_runner import run_zeek


def connection(uid="C1", timestamp=1000, destination="203.0.113.10", **overrides):
    record = {"ts": timestamp, "uid": uid, "id.orig_h": "192.168.1.10", "id.orig_p": 51000,
              "id.resp_h": destination, "id.resp_p": 443, "proto": "tcp", "service": "ssl",
              "duration": 60, "orig_bytes": 1000, "resp_bytes": 60 * 1024 * 1024,
              "orig_pkts": 20, "resp_pkts": 1000, "conn_state": "SF"}
    record.update(overrides)
    return record


def protocol_record(flow, **data):
    return {**{key: flow[key] for key in ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p")}, **data}


def dns(timestamp=998, domain="www.youtube.com", answer="203.0.113.10", ttl=120, **overrides):
    record = {"ts": timestamp, "uid": "DNS1", "id.orig_h": "192.168.1.10", "id.orig_p": 52000,
              "id.resp_h": "8.8.8.8", "id.resp_p": 53, "query": domain,
              "answers": [answer], "TTLs": [ttl], "rcode_name": "NOERROR", "qtype_name": "A"}
    record.update(overrides)
    return record


def write_logs(directory, **logs):
    for name, records in logs.items():
        (directory / f"{name}.log").write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def analyze(self, config=None, **logs):
        write_logs(self.directory, **logs)
        return _analyze_logs(self.directory, config or AnalysisConfig(), "fixture.pcap")

    def test_youtube_story_and_graph_contract(self):
        first = connection(resp_bytes=1000)
        video = connection("C2", 1005, "203.0.113.20")
        result = self.analyze(
            conn=[first, video],
            dns=[dns(), dns(1003, "r1.googlevideo.com", "203.0.113.20")],
            ssl=[protocol_record(first, server_name="www.youtube.com", version="TLSv13"),
                 protocol_record(video, server_name="r1.googlevideo.com", version="TLSv13")],
        )
        json.dumps(result, allow_nan=False)
        self.assertEqual(set(result), {"summary", "activities", "nodes", "edges"})
        streaming = [item for item in result["activities"] if item["type"] == "possible_streaming"]
        self.assertEqual(len(streaming), 1)
        self.assertEqual(streaming[0]["statistics"]["bytes_received"], 1000 + 60 * 1024 * 1024)
        self.assertEqual(len(streaming[0]["flow_ids"]), 2)
        self.assertEqual(len(streaming[0]["evidence"]), 6)
        ids = {node["id"] for node in result["nodes"]}
        self.assertEqual(len(ids), len(result["nodes"]))
        for edge in result["edges"]:
            self.assertIn(edge["source"], ids)
            self.assertIn(edge["target"], ids)
        self.assertIsNone(result["summary"]["packet_count"])
        self.assertEqual(result["summary"]["connection_packet_count"], 2040)
        self.assertEqual(result, _analyze_logs(self.directory, AnalysisConfig(), "fixture.pcap"))

    def test_dns_is_scoped_to_client_and_time(self):
        for query in (dns(ttl=1), dns(timestamp=1100), dns(**{"id.orig_h": "192.168.1.99"})):
            with self.subTest(query=query):
                result = self.analyze(conn=[connection()], dns=[query])
                connection_activity = next(a for a in result["activities"] if a["flow_ids"])
                self.assertEqual(connection_activity["domains"], [])

    def test_sni_disambiguates_shared_ip(self):
        flow = connection()
        result = self.analyze(conn=[flow], dns=[dns(domain="unrelated.example")],
                              ssl=[protocol_record(flow, server_name="actual.example")])
        activity = next(a for a in result["activities"] if a["flow_ids"])
        self.assertEqual(activity["domains"], ["actual.example"])

    def test_dns_does_not_attribute_queried_domain_to_resolver(self):
        resolver = connection("DNS1", 998, "8.8.8.8", **{"id.resp_p": 53, "resp_bytes": 100})
        result = self.analyze(conn=[resolver], dns=[dns()])
        self.assertEqual(result["activities"][0]["type"], "dns_activity")
        self.assertFalse(any(edge["label"] == "Observed service endpoint" for edge in result["edges"]))

    def test_service_suffix_does_not_match_lookalikes(self):
        self.assertFalse(domain_matches("notyoutube.com", "youtube.com"))
        self.assertFalse(domain_matches("youtube.com.attacker.example", "youtube.com"))
        self.assertTrue(domain_matches("www.youtube.com", "youtube.com"))

    def test_port_443_alone_does_not_establish_tls(self):
        result = self.analyze(conn=[connection(resp_bytes=100)])
        self.assertEqual(result["activities"][0]["type"], "network_connection")
        self.assertFalse(any(edge["type"] == "TLS" for edge in result["edges"]))

    def test_unknown_counters_remain_unknown(self):
        record = connection()
        del record["resp_bytes"]
        del record["resp_pkts"]
        result = self.analyze(conn=[record])
        self.assertIsNone(result["summary"]["bytes_received"])
        self.assertIsNone(result["summary"]["connection_packet_count"])
        self.assertIsNone(result["activities"][0]["statistics"]["bytes_received"])

    def test_graph_limit_preserves_full_story(self):
        result = self.analyze(AnalysisConfig(max_graph_activities=1),
                              conn=[connection(), connection("C2", 2000)])
        self.assertEqual(len(result["activities"]), 2)
        self.assertTrue(result["summary"]["graph_truncated"])
        self.assertEqual(sum(node["type"] == "activity" for node in result["nodes"]), 1)

    def test_ipv6_and_http_host(self):
        flow = connection(destination="2001:db8::1", **{"id.orig_h": "2001:db8::2", "resp_bytes": 20})
        result = self.analyze(conn=[flow], http=[protocol_record(flow, host="Example.COM:80", method="GET")])
        self.assertEqual(result["activities"][0]["domains"], ["example.com"])
        self.assertTrue(any(edge["type"] == "HTTP" for edge in result["edges"]))

    def test_empty_logs_return_explicit_empty_result(self):
        result = self.analyze()
        self.assertEqual(result["activities"], [])
        self.assertEqual(result["nodes"], [])
        self.assertIsNone(result["summary"]["start_time"])
        self.assertTrue(result["summary"]["warnings"])

    def test_duplicate_uids_and_invalid_metrics_rejected(self):
        for records in ([connection(), connection()], [connection(resp_bytes=-1)],
                        [connection(ts=float("inf"))], [connection(uid=None)]):
            with self.subTest(records=records), self.assertRaises(ValueError):
                build_flows(records)

    def test_public_function_orchestrates_and_cleans_up(self):
        capture = self.directory / "capture with spaces.pcap"
        capture.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        flow = connection()

        def fake_zeek(command, **kwargs):
            self.assertEqual(command, ["zeek", "-r", str(capture.resolve()), "LogAscii::use_json=T"])
            self.assertNotIn("shell", kwargs)
            logs = Path(kwargs["cwd"])
            self.created_logs = logs
            write_logs(logs, conn=[flow], ssl=[protocol_record(flow, server_name="example.com")])
            return subprocess.CompletedProcess(command, 0, "", "test diagnostic")

        with patch("pcap_story.zeek_runner.subprocess.run", side_effect=fake_zeek):
            result = get_flowchart(capture)
        self.assertEqual(result["summary"]["connection_count"], 1)
        self.assertIn("test diagnostic", result["summary"]["warnings"])
        self.assertFalse(self.created_logs.exists())

    def test_capture_validation_before_execution(self):
        with patch("pcap_story.flowchart.run_zeek") as runner:
            with self.assertRaises(FileNotFoundError):
                get_flowchart(self.directory / "missing.pcap")
            for name, content in (("bad.pcap", b"not a capture"), ("bad.txt", b"\xd4\xc3\xb2\xa1")):
                path = self.directory / name
                path.write_bytes(content)
                with self.assertRaises(ValueError):
                    get_flowchart(path)
            runner.assert_not_called()

    def test_failed_runtime_and_timeout_never_return_success(self):
        for failure in (FileNotFoundError(), subprocess.TimeoutExpired("zeek", 1)):
            with self.subTest(failure=failure):
                with patch("pcap_story.zeek_runner.subprocess.run", side_effect=failure):
                    with self.assertRaises(ZeekError):
                        with run_zeek(self.directory / "sample.pcap", AnalysisConfig()):
                            self.fail("Failed Zeek must not yield logs")
        with patch("pcap_story.zeek_runner.subprocess.run", return_value=subprocess.CompletedProcess("zeek", 1, "", "bad capture")):
            with self.assertRaisesRegex(ZeekError, "bad capture"):
                with run_zeek(self.directory / "sample.pcap", AnalysisConfig()):
                    self.fail("Failed Zeek must not yield logs")

    def test_wsl_command_translates_both_paths(self):
        def fake_process(command, **kwargs):
            if "wslpath" in command:
                return subprocess.CompletedProcess(command, 0, "/mnt/d/translated\n", "")
            self.assertEqual(command[:3], ["wsl.exe", "--distribution", "Ubuntu"])
            self.assertIn("--cd", command)
            self.assertIn("--exec", command)
            self.assertIn("-C", command)
            return subprocess.CompletedProcess(command, 0, "", "")
        with patch("pcap_story.zeek_runner.subprocess.run", side_effect=fake_process):
            with run_zeek(self.directory / "sample.pcap", AnalysisConfig(runtime="wsl", wsl_distribution="Ubuntu", ignore_checksums=True)) as (directory, _):
                self.assertTrue(directory.is_dir())
            self.assertFalse(directory.exists())


class ParserTests(unittest.TestCase):
    def test_tsv_types_unset_sets_and_escaped_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dns.log"
            path.write_text(
                "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
                "#fields\tts\tanswers\tTTLs\tflag\toptional\ttext\n"
                "#types\ttime\tvector[addr]\tvector[interval]\tbool\tstring\tstring\n"
                "1000.5\t203.0.113.1,203.0.113.2\t60,120\tT\t-\thello\\x20world\n",
                encoding="utf-8")
            record, = read_log(path)
            self.assertEqual(record["TTLs"], [60, 120])
            self.assertIsNone(record["optional"])
            self.assertEqual(record["text"], "hello world")
            self.assertIs(record["flag"], True)

    def test_invalid_log_has_filename_and_line_number(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "conn.log"
            for content in ('{"ts":NaN}', '{"ts":1e400}', '{broken}', 'no headers\there'):
                path.write_text(content, encoding="utf-8")
                with self.subTest(content=content), self.assertRaisesRegex(ValueError, "conn.log:1:"):
                    list(read_log(path))


if __name__ == "__main__":
    unittest.main()
