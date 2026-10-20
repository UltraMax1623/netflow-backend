"""Live capture boundaries; no real network capture in tests."""
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from main import app
from pcap_story import live_capture as live


class LiveCaptureTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app, base_url="http://localhost", client=("127.0.0.1", 12345))

    def test_interfaces(self):
        output = subprocess.CompletedProcess([], 0, "1. eth0 (Ethernet)\n2. lo\n", "")
        with patch.object(live, "dumpcap_binary", return_value="dumpcap"), patch.object(live, "_run", return_value=output):
            response = self.client.get("/api/live/interfaces")
        self.assertEqual(response.json()["interfaces"], [
            {"id": "eth0", "label": "Ethernet"}, {"id": "lo", "label": "lo"}])

    def test_local_and_origin_restrictions(self):
        for client, headers in [
            (TestClient(app, base_url="http://localhost", client=("192.0.2.1", 1)), {}),
            (self.client, {"origin": "https://example.com"}),
            (self.client, {"host": "example.com"}),
        ]:
            self.assertEqual(client.get("/api/live/interfaces", headers=headers).status_code, 403)

    def test_validation(self):
        for settings in [
            {"interface": "eth0", "seconds": 0},
            {"interface": "eth0", "seconds": 61},
            {"interface": "eth0", "seconds": 5.5},
            {"interface": ""},
            {"interface": "eth0", "capture_filter": "tcp\x00"},
        ]:
            self.assertEqual(self.client.post("/api/live/capture", json=settings).status_code, 422)

    def test_capture_analysis_limits_and_cleanup(self):
        paths = []

        def capture(command, timeout):
            self.assertEqual(live.capture_status()["phase"], "capturing")
            path = Path(command[command.index("-w") + 1])
            paths.append(path)
            self.assertIn("duration:5", command)
            self.assertIn("filesize:25000", command)
            self.assertIn("100000", command)
            self.assertEqual(command[-2:], ["-f", "tcp or udp"])
            self.assertEqual(timeout, 20)
            path.write_bytes(b"capture")

        def analyze(file, ignore_checksums, thresholds):
            self.assertEqual(live.capture_status()["phase"], "analyzing")
            self.assertTrue(ignore_checksums)
            self.assertEqual(file.file.read(), b"capture")
            return {"summary": {"warnings": []}, "nodes": [], "edges": [], "activities": []}

        with patch.object(live, "dumpcap_binary", return_value="dumpcap"), \
             patch.object(live, "list_interfaces", return_value=[{"id": "eth0"}]), \
             patch.object(live, "_run", side_effect=capture), \
             patch("main.analyze_upload", side_effect=analyze):
            response = self.client.post("/api/live/capture", json={
                "interface": "eth0", "seconds": 5, "capture_filter": "tcp or udp"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["summary"]["capture_mode"], "live_window")
        self.assertFalse(paths[0].parent.exists())
        self.assertEqual(self.client.get("/api/live/status").json(), {"phase": "idle"})

    def test_invalid_adapter_and_busy(self):
        with patch.object(live, "dumpcap_binary", return_value="dumpcap"), \
             patch.object(live, "list_interfaces", return_value=[]):
            with self.assertRaises(HTTPException) as error:
                with live.capture_window("unknown", 5, ""):
                    self.fail("Must not capture")
            self.assertEqual(error.exception.status_code, 400)
        live._capture_lock.acquire()
        try:
            with self.assertRaises(HTTPException) as error:
                with live.capture_window("eth0", 5, ""):
                    self.fail("Must not capture")
            self.assertEqual(error.exception.status_code, 409)
        finally:
            live._capture_lock.release()

    def test_failure_cleans_directory_and_releases_lock(self):
        paths = []

        def fail(command, timeout):
            paths.append(Path(command[command.index("-w") + 1]))
            raise HTTPException(502, "Capture failed")

        with patch.object(live, "dumpcap_binary", return_value="dumpcap"), \
             patch.object(live, "list_interfaces", return_value=[{"id": "eth0"}]), \
             patch.object(live, "_run", side_effect=fail):
            for _ in range(2):
                with self.assertRaises(HTTPException):
                    with live.capture_window("eth0", 5, ""):
                        self.fail("Must fail")
        self.assertTrue(all(not path.parent.exists() for path in paths))
        self.assertFalse(live._capture_lock.locked())

    def test_subprocess_errors(self):
        for error, status in [(FileNotFoundError(), 503),
                              (subprocess.TimeoutExpired("dumpcap", 5), 504)]:
            with patch.object(live.subprocess, "run", side_effect=error):
                with self.assertRaises(HTTPException) as raised:
                    live._run(["dumpcap"], 5)
                self.assertEqual(raised.exception.status_code, status)
        with patch.object(live.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "permission denied")):
            with self.assertRaises(HTTPException) as raised:
                live._run(["dumpcap"], 5)
            self.assertEqual(raised.exception.status_code, 502)
