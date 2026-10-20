"""HTTP contract and temporary upload lifecycle verification."""
import os
import struct
import subprocess
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from main import app
from pcap_story import ZeekError

CAPTURE = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

class FlowchartApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def upload(self, name='sample.pcap', data=CAPTURE):
        return self.client.post('/api/flowchart', files={'file': (name, data)})

    def test_dashboard(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('flow-graph', response.text)
        self.assertEqual(self.client.get('/dashboard-ui.js').status_code, 200)

    def test_capture_analytics_and_settings(self):
        from io import BytesIO
        import dpkt
        output = BytesIO()
        writer = dpkt.pcap.Writer(output)
        writer.writepkt(bytes(dpkt.ethernet.Ethernet(type=0x806, data=dpkt.arp.ARP())), ts=1)
        with patch('main.get_flowchart', return_value={'summary': {}, 'activities': [], 'nodes': [], 'edges': []}):
            response = self.client.post('/api/flowchart', files={'file': ('arp.pcap', output.getvalue())},
                                        data={'settings': '{"pps_threshold":500}'})
        self.assertEqual(response.status_code, 200)
        result = response.json()['analytics']
        self.assertEqual(result['summary']['total_packets'], 1)
        self.assertEqual(result['protocols']['ARP'], 1)
        self.assertEqual(result['security']['thresholds']['pps_threshold'], 500)
        response = self.client.post('/api/flowchart', files={'file': ('arp.pcap', output.getvalue())},
                                    data={'settings': '{"gateway_ip":"invalid"}'})
        self.assertEqual(response.status_code, 422)

    def test_success_formats_configuration_and_cleanup(self):
        paths = []
        def analyze(path, config):
            paths.append(path)
            self.assertEqual(path.read_bytes(), CAPTURE)
            self.assertEqual(config.runtime, 'wsl')
            self.assertEqual(config.wsl_distribution, 'Ubuntu')
            self.assertEqual(config.timeout_seconds, 42)
            return {'summary': {}, 'activities': [], 'nodes': [], 'edges': []}
        with patch.dict(os.environ, {'PCAP_ZEEK_RUNTIME': 'wsl', 'PCAP_ZEEK_DISTRIBUTION': 'Ubuntu', 'PCAP_ZEEK_TIMEOUT': '42'}), patch('main.get_flowchart', side_effect=analyze):
            for suffix in ('.pcap', '.pcapng', '.cap'):
                response = self.upload('../../sample' + suffix)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['summary']['pcap'], 'sample' + suffix)
        self.assertTrue(all(not path.parent.exists() for path in paths))
        self.assertEqual(len(set(paths)), 3)

    def test_invalid_and_missing_upload(self):
        self.assertEqual(self.upload('bad.txt').status_code, 400)
        self.assertEqual(self.upload(data=b'invalid').status_code, 400)
        self.assertEqual(self.client.post('/api/flowchart').status_code, 422)

    def test_runtime_errors_and_cleanup(self):
        for cause, expected in ((FileNotFoundError(), 503), (subprocess.TimeoutExpired('zeek', 1), 504), (None, 502)):
            paths = []
            def fail(path, config):
                paths.append(path)
                raise ZeekError('Zeek failed') from cause
            with patch('main.get_flowchart', side_effect=fail):
                response = self.upload()
            self.assertEqual(response.status_code, expected)
            self.assertTrue(all(not path.parent.exists() for path in paths))
            self.assertIn('Zeek failed', response.json()['detail'])

    def test_invalid_server_configuration(self):
        with patch.dict(os.environ, {'PCAP_ZEEK_TIMEOUT': 'invalid'}):
            self.assertEqual(self.upload().status_code, 503)

    def test_oversized_upload_cleanup(self):
        from io import BytesIO
        from fastapi import HTTPException, UploadFile
        from main import analyze_upload
        class LargeChunk(bytes):
            def __len__(self):
                return 501 * 1024 * 1024
        class Oversized(BytesIO):
            def read(self, size=-1):
                return LargeChunk(b'x')
        with self.assertRaises(HTTPException) as raised:
            analyze_upload(UploadFile(filename='large.pcap', file=Oversized()))
        self.assertEqual(raised.exception.status_code, 413)
