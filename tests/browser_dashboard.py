"""Optional browser checks: PYTHONPATH=.test-deps python tests/browser_dashboard.py.

Requires Playwright and an installed Chromium/Edge browser. Network access is
needed for the dashboard's existing CDNs. API data is a clearly synthetic fixture.
"""
import json
import os
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import threading

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        if self.path == "/":
            self.path = "/dashboard.html"
        super().do_GET()

    def log_message(self, *args):
        pass


def fixture():
    connections = [{
        "id": f"flow-{i}", "uid": f"C{i}", "source_ip": "10.0.0.1",
        "destination_ip": f"192.0.{i // 250}.{i % 250 + 1}", "source_port": 1000 + i,
        "destination_port": 443, "protocol": "tcp", "service": "ssl",
        "domain": f"site-{i // 2}.example", "start": 1000, "end": 1010,
        "bytes_sent": 100, "bytes_received": 1000, "packets_sent": 1,
        "packets_received": 2, "state": "SF"
    } for i in range(400)]
    return {
        "summary": {"pcap": "browser-fixture.pcap", "activity_count": 0, "warnings": []},
        "nodes": [], "edges": [], "activities": [], "connections": connections,
        "analytics": {
            "summary": {"total_packets": 1200, "total_bytes": 440000, "duration": 10,
                        "average_pps": 120, "start_time": 1000, "end_time": 1010,
                        "unique_sources": 1, "unique_destinations": 400},
            "protocols": {"TCP": 1200}, "services": {"TLS port": 1200},
            "packet_sizes": {"65–128": 400, "1025–1518": 800}, "bin_seconds": 1,
            "top_sources": {"10.0.0.1": 1200}, "top_destinations": {"192.0.0.1": 3},
            "timeline": [{"time": 1000 + i, "pps": 120, "mbps": 0.352} for i in range(10)],
            "tcp": {"syn_packets": 400, "syn_ack_packets": 400, "unique_syn_attempts": 400,
                    "completed_handshakes": 400, "resets": 0},
            "security": {"status": "clear", "findings": [], "warnings": [], "thresholds": {},
                         "coverage": ["Synthetic browser fixture; no real network capture."]}
        }
    }


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with sync_playwright() as p:
        edge = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
        browser = p.chromium.launch(headless=True, **({"executable_path": str(edge)} if edge.exists() else {}))
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, device_scale_factor=1)
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/api/flowchart", lambda route: route.fulfill(json=fixture()))
        page.route("**/api/live/interfaces", lambda route: route.fulfill(json={"interfaces": [{"id": "eth0", "label": "Test adapter"}]}))
        page.route("**/api/live/capture", lambda route: route.fulfill(json=fixture()))
        page.goto(f"http://127.0.0.1:{server.server_port}/", wait_until="networkidle")
        page.wait_for_function("typeof cytoscape === 'function' && typeof Chart === 'function'")
        assert page.locator("#health-title").inner_text() == "Traffic summary — waiting for capture"
        page.locator("#file-input").set_input_files({"name": "fixture.pcap", "mimeType": "application/octet-stream", "buffer": b"test"})
        page.wait_for_function("latestResult !== null && graph !== null")
        assert page.evaluate("graph.edges().length") == 80
        assert page.evaluate("chartInstances.protocolChart.data.datasets[0].data[0]") == 1200
        assert page.locator("#traffic-health").get_attribute("data-state") == "clear"
        assert page.evaluate("graph.nodes('[type=\"activity\"]').length") == 0
        page.evaluate("graph.edges()[0].emit('tap')")
        assert "Connections" in page.locator("#graph-details").inner_text()
        assert not page.locator("#graph-details pre").inner_text()
        page.locator("#graph-details summary", has_text="View raw data").click()
        page.wait_for_function("document.querySelector('#graph-details pre').textContent.includes('flow-')")
        assert "flow-" in page.locator("#graph-details pre").inner_text()
        page.locator("#graph-search").fill("site-100.example")
        page.wait_for_function("graph.edges().length === 1")
        assert "2 connections" in page.evaluate("graph.edges()[0].data('label')")
        page.locator("#graph-search").fill("")
        page.wait_for_function("graph.edges().length === 80")
        page.locator("#graph-limit").select_option("150")
        page.wait_for_function("graph.edges().length === 150")
        for width in (390, 1440, 1920):
            page.set_viewport_size({"width": width, "height": 1000})
            page.wait_for_timeout(300)
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert page.locator("#flow-graph").bounding_box()["height"] <= 541
            assert page.locator("#trafficChart").bounding_box()["height"] < 200
        page.set_viewport_size({"width": 1440, "height": 1000})
        page.locator('nav a[href="#settings"]').click()
        page.locator('input[name="pps_threshold"]').fill("5000")
        page.locator('#detection-settings button[type="submit"]').click()
        assert "next" in page.locator("#settings-status").inner_text()
        page.locator('nav a[href="#reports"]').click()
        with page.expect_download() as info:
            page.locator("#download-report").click()
        assert info.value.suggested_filename.endswith(".txt")
        page.evaluate("document.querySelector('#flow-section').scrollIntoView()")
        page.screenshot(path=str(ROOT / ".test-tmp" / "dashboard-graph.png"))
        page.locator("#graph-search").fill("site-100.example")
        page.wait_for_function("graph.edges().length === 1")
        page.evaluate("graph.edges()[0].emit('tap')")
        page.screenshot(path=str(ROOT / ".test-tmp" / "dashboard-details.png"))
        page.locator("#graph-search").fill("")
        page.locator("#load-adapters").click()
        page.wait_for_function("document.querySelector('#live-interface').value === 'eth0'")
        page.locator("#start-live").click()
        page.locator("#stop-live").click()
        page.wait_for_function("!processing")
        assert "Stopped" in page.locator("#live-status").inner_text()
        page.unroute("**/api/flowchart")
        page.route("**/api/flowchart", lambda route: route.fulfill(status=503, json={"detail": "Zeek unavailable"}))
        page.locator("#file-input").set_input_files({"name": "failure.pcap", "mimeType": "application/octet-stream", "buffer": b"test"})
        page.wait_for_function("document.querySelector('#traffic-health').dataset.state === 'error'")
        assert not errors, errors
        browser.close()
    server.shutdown()
    print("Browser checks passed: real chart wiring, grouping, details, filters, exports, live stop, error state, and three viewport widths.")


if __name__ == "__main__":
    main()
