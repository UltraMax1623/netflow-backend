# PCAP story analysis package

The analysis package is integrated with the FastAPI backend and dashboard.
The offline analysis pipeline uses Python's standard library (Python 3.10+);
the live capture adapter also uses FastAPI for HTTP errors.

## Public interface

```python
from pcap_story import get_flowchart

result = get_flowchart("capture.pcap")
```

Accepts `.pcap`, `.pcapng`, or `.cap` files. Returns a Python dictionary with
`summary`, `activities`, `nodes`, and `edges`. No JSON file is created by default.
The caller can return it from FastAPI or serialize it using `json.dumps`.

## Pipeline

`get_flowchart` validates the capture header, runs Zeek with JSON logging in an
isolated temporary directory, parses connection/DNS/TLS/HTTP logs, normalizes
flows and events, correlates evidence, applies activity rules, orders the story,
and generates an aggregated graph. Temporary logs are deleted on success or error.
There is no shared mutable analysis state and no live enrichment/network lookup.

Modules:

- `config.py`: explicit runtime configuration and thresholds.
- `models.py`: Flow, Event, ActivityGroup, stable IDs, domain normalization.
- `zeek_runner.py`: native or explicitly configured WSL execution, timeout/errors.
- `zeek_parser.py`: line-oriented JSON or standard Zeek TSV logs.
- `flow_builder.py`: connection normalization; connection counters counted once.
- `event_extractor.py`: observed connection, DNS, TLS, HTTP facts and provenance.
- `correlator.py`: connection UID joins and client/IP/time/TTL-scoped DNS joins.
- `detector.py`: conservative activity labels, evidence, statistics, rule confidence.
- `story_generator.py`: chronological sequence.
- `graph_builder.py`: unique nodes/edges with activity references.
- `flowchart.py`: public orchestration and summary.

## Zeek setup

Zeek is an external prerequisite, not a Python dependency. Install it in the
environment that will run the analysis. Native execution expects `zeek` on PATH:

```powershell
python test.py "D:\captures\sample.pcap"
python test.py "D:\captures\sample.pcapng" --output "story.json"
```

`--output` creates a new file and refuses to overwrite an existing file.
For Windows with a working WSL distribution containing Zeek:

```powershell
python test.py "D:\captures\sample.pcap" --runtime wsl --distribution Ubuntu
```

Paths are translated with `wslpath`; the capture and temporary log directories
must be accessible to that distribution. No WSL installation is performed.
An absolute executable path can be supplied with `--zeek-binary` (use a Linux
path with WSL). Increase `--timeout` for large captures. `--ignore-checksums`
explicitly enables Zeek's `-C` option for captures affected by checksum offload.
Arguments are passed without a shell.

Equivalent Python configuration:

```python
from pcap_story import AnalysisConfig, get_flowchart

result = get_flowchart(
    "capture.pcap",
    config=AnalysisConfig(
        runtime="wsl",
        wsl_distribution="Ubuntu",
        timeout_seconds=1200,
        max_graph_activities=100,
    ),
)
```

Official Zeek command/log documentation:
https://docs.zeek.org/en/current/tutorial/logs.html

## Output contract, version 1.1

Top-level keys:

- `connections`: one record per normalized Zeek connection, with its counters
  and a domain only when TLS/HTTP evidence identifies one unambiguous domain.
  `observed_domains` retains all observed names. The dashboard aggregates these
  records by initiator and domain (or server IP), without counting a connection twice.
  The HTTP API also adds `analytics`: independent frame statistics, bounded
  timeline charts, TCP handshake counters, and security indicators.

- `summary`: capture name, observed start/end/duration, counts, directional
  connection bytes, graph truncation, tool diagnostics, and warnings.
- `activities`: complete chronological story. Every activity includes a stable
  ID, type/title, source, domains/destinations, start/end, sequence, confidence,
  rule reason, statistics, flow IDs, and full normalized evidence records.
- `nodes`: `{id, type, label, data}`. Current types: `host`, `domain`, `server`,
  `activity`. `alert` is reserved for future evidence-backed security detectors.
- `edges`: `{id, source, target, type, label, data}`. Current types:
  `DNS_QUERY`, `CONNECTED_TO`, `TLS`, `HTTP`, `RELATED_TO`.
  `DATA_TRANSFER` is reserved; current transfer statistics live on activities.

Evidence records have `id`, `timestamp`, `type`, `uid`, `source`, `destination`,
`data`, and `source_tool`. `data.log` identifies the original Zeek log.
Activity evidence is embedded so the frontend can resolve it without another API.
All timestamps are UNIX seconds in UTC; durations are seconds and sizes are bytes.
Missing counters are `null`, never fabricated zeros.

`host` and `server` describe observed initiator/responder roles; they do not assert
that an address is internal or external. A host acting in both roles gets one
IP node. Nodes have no positions: the frontend supplies layout and custom types.
Edge `data.activity_ids` links to activities for click-through evidence.
Edges express observed relationships, not a proven causal sequence.

Only the first `max_graph_activities` chronological activities enter the graph;
`activities` always retains the full story and `summary.graph_truncated` makes
the limit explicit. This bounds activities represented, not the absolute node
count: a single activity can involve many endpoints. Consumers can build further
overview/activity/detail views using the returned activity references.

## Rules and limits

Initial rules identify DNS observations, web/TLS observations, large inbound or
outbound transfers (default 50 MiB), and possible YouTube streaming. The latter
requires YouTube plus googlevideo domain evidence, TLS/HTTP evidence, a large
inbound transfer, and an activity interval of at least 30 seconds. An interval
and total volume do not prove uninterrupted streaming, a particular video, or
user intent. Confidence values describe rule strength, not measured probability.
No LLM, malware verdict, baseline-based exfiltration verdict, port-scan detector,
or beaconing detector is included in this first version.

DNS evidence is scoped to the querying client and answered IP, must precede the
connection, and expires at the smaller of the logged TTL and 300 seconds. TLS
SNI/HTTP Host takes precedence over other domains sharing an IP. Subdomain
matches respect label boundaries. An unanswered/failed query alone is not a
website visit. Missing DNS, encrypted DNS/SNI, unsupported protocols, packet
loss, or mid-session captures reduce what can be inferred. QUIC is not inferred
from UDP port 443 alone.

`packet_count` is `null`: connection counters do not count every capture frame.
`connection_packet_count` sums Zeek originator/responder packet counters when
all are available. Byte counters are Zeek connection payload metrics, not PCAP
file size or whole-frame totals. `duration` spans observed supported records.
The HTTP API now adds independent `dpkt` capture-wide frame statistics under
`analytics`, without double-counting Zeek flows.

Log files are read line by line, but normalized records and the full activity
story remain in memory. This version is not a bounded-memory, multi-gigabyte
processing service. Backend job scheduling/persistence belongs to the hosting
application. Optional cached IP ownership/reputation/reverse-DNS enrichment is
the next extension; enrichment failures must remain nonfatal and attribution
must not equate IP ownership or reverse DNS with a visited website.

## Errors and verification

Missing input raises `FileNotFoundError`; bad format/records raise `ValueError`
(missing required log fields can raise `KeyError`). Zeek setup, timeout, or
nonzero exit raises `pcap_story.ZeekError`. Missing optional protocol logs are
normal; no connection records yields a warning and the available observations.
The CLI reports failures to stderr and exits nonzero, without producing a success
object. It does not alter the existing backend's error handling or routes.

Run the offline tests:

```powershell
python -m unittest discover -s tests -v
```

The tests use representative generated Zeek records, including a mocked
subprocess-to-public-API integration. They verify evidence correlation, TTL/client
isolation, shared-IP SNI precedence, suffix safety, IPv6/HTTP, unknown counters,
graph consistency/limits, TSV/JSON parsing, input checks, subprocess failures,
WSL command construction, and temporary-directory cleanup. They do not substitute
for running an actual capture through an installed Zeek runtime.

## Interactive website

Run `python -m pip install -r requirements.txt`, then `python -m uvicorn main:app --reload` from the repository root. Open http://127.0.0.1:8000 and upload a .pcap, .pcapng, or .cap capture. All charts and protocol counters use the current capture. Internet access is required for the pinned Cytoscape 3.30.4 and existing styling/chart CDNs.

For Windows, install WSL and Zeek in a Linux distribution first. Check `wsl --distribution Ubuntu --exec zeek --version`, then configure the server:

```powershell
$env:PCAP_ZEEK_RUNTIME = 'wsl'
$env:PCAP_ZEEK_DISTRIBUTION = 'Ubuntu'
$env:PCAP_ZEEK_BINARY = 'zeek'
$env:PCAP_ZEEK_TIMEOUT = '600'
python -m uvicorn main:app --reload
```

Use an absolute Linux path for PCAP_ZEEK_BINARY if Zeek is absent from WSL's noninteractive PATH. Native installations default to runtime native, binary zeek, and a 600-second timeout.

POST /api/flowchart accepts multipart field file and returns summary, activities, nodes, and edges. Errors: invalid captures 400, uploads over 500 MB 413, missing uploads 422, unavailable runtime/configuration 503, analysis failures 502, timeout 504. Capture uploads and Zeek logs are temporary and cleaned after success or failure. The existing statistics endpoint is preserved.

Zoom with the mouse wheel, pan by dragging the background, drag nodes, and click nodes/connections for activity details and evidence. Fit and reset-layout controls restore the view. Warnings include empty results and graph truncation (100 activities by default); the response retains all activities. No capture history is saved.

Tests: install httpx, then run `python -m unittest discover -s tests -v`.

## Live network capture

For installation, startup, and a real capture smoke test on Ubuntu, see
[UBUNTU_SETUP.md](UBUNTU_SETUP.md).

The dashboard supports repeated, bounded captures from the **server machine's**
network adapter. Run one server worker and open `http://127.0.0.1:8000`.
Click **Refresh adapters**, select Wi-Fi/Ethernet, optionally enter a BPF capture
filter such as `tcp or udp`, then click **Start live capture**. Section 4 shows
the latest real flowchart. All charts, counters and security findings update
from the same capture window.

On Windows, install Wireshark with Npcap and grant the current account capture
permissions. The backend finds dumpcap on PATH or in the standard
`C:\Program Files\Wireshark` directory. For another installation location:

```powershell
$env:PCAP_DUMPCAP_BINARY = 'C:\Program Files\Wireshark\dumpcap.exe'
$env:PCAP_ZEEK_RUNTIME = 'wsl'
$env:PCAP_ZEEK_DISTRIBUTION = 'Ubuntu'
# Zeek must already be installed in this distribution.
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Linux/macOS use native dumpcap with capture permissions and native Zeek.
Adapter capture happens on the host even when Zeek runs inside WSL.
See the [official dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html)
for installation-specific capture options and filters.

`GET /api/live/interfaces` lists adapters; `POST /api/live/capture` accepts
`{"interface":"<adapter id>","seconds":10,"capture_filter":""}`. Both endpoints
require a loopback client and localhost/loopback Host; browser requests must be
same-origin. Keep this application bound to loopback, without a public reverse
proxy. Only one live request runs at a time per server process.

Each window lasts 5–60 seconds (default 10), stopping earlier at 25 MB or
100,000 packets. Capture and Zeek files are temporary and cleaned on success or
failure. Capture errors are displayed, including missing dependencies,
permissions, invalid filters, and timeouts. Local checksum offload is handled
by disabling Zeek checksum validation for live windows.

This is **windowed live analysis**, not a lossless continuous monitor. Capture
pauses while Zeek analyzes the previous window. The graph replaces the previous
window; DNS context and connections spanning windows may be incomplete.
**Stop after this window** waits for capture and analysis to finish. Closing
the page prevents subsequent windows; the current server request can finish
within the capture and configured Zeek timeouts. There is no capture history.
The adapter only sees traffic available to it, not every device on the network.

## Dashboard and security assessment

The two-column dashboard retains its protocol cards and device/globe/server
icons. Sidebar entries link to Analysis, Reports, Settings and Help. Reports
export a readable text summary or the complete JSON evidence. Nothing is saved
on the server after analysis.

The main graph hides generic activity boxes, combines repeated connections by
client/domain or client/server, and provides client, domain/IP/service, and
DNS-only filters. It draws at most 40/80/150 connection groups (80 by default),
with an explicit displayed/total count. The full analysis remains exportable.
Large graphs start at a readable scale with pan/zoom; Fit provides an overview.
The graph and details panel have bounded dimensions. Raw JSON is available only
inside an optional details toggle.

Eight real charts show throughput, protocol counts, packet share, packet sizes,
packet/SYN/ICMP rates, top destinations, TCP handshakes and top sources.
Frame bytes are captured lengths, not necessarily wire lengths when snaplen
truncates frames; Zeek connection bytes are payload counters and differ.
Timeline bins are at least one second and grow to keep at most 121 points.
Average PPS uses total packets / observed duration; zero-duration captures
report an unavailable average instead of dividing by zero.

Security checks are investigation heuristics, **not confirmed attack verdicts**:

- Packet/ICMP rate thresholds flag unusually high volume. A configured normal
  PPS baseline also requires a 3× increase. No automatic baseline is learned.
- TCP handshake completion uses completed observed three-way handshakes divided
  by distinct SYN attempts. Retransmitted SYNs are counted in traffic totals
  but deduplicated for completion. Missing replies and window boundaries matter.
- ARP changes flag conflicting IP/MAC mappings. A configured gateway IP/MAC
  baseline supports a stronger gateway mismatch warning.
- Visible UDP DNS is matched by client, port, transaction ID and question for
  10 seconds. Conflicting answer sets or unexpected reply sources are review
  items. Identical retransmissions and TTL changes alone are not flagged.
- A complete plaintext HTTP request carrying an HTTPS referrer is a downgrade
  lead. Encrypted redirects and TLS stripping cannot be confirmed here.
- Bursts of distinct connections to port 22 are possible brute-force leads.
  Failed passwords, usernames, and a successful login require authentication logs.

Red indicates a high-priority heuristic or an explicitly labeled processing
error. Amber indicates review items or incomplete decode coverage. Green means
no configured indicators were found, **not a clean bill of health**. Empty
captures remain neutral. Settings affect the next upload or live session.
API callers can pass JSON in multipart `settings`, or a `settings` object in
the live capture request. Defaults and the applied settings are in each report.

Limitations: no TCP/IP reassembly in packet checks, no decryption, no learned
baseline or persistent live-window history. Detector state is capped at 100,000
entries per state table; reaching the limit is reported. The Zeek pipeline still
retains normalized logs in memory. Packet-level analytics support Ethernet,
Linux cooked v1/v2, raw IP and loopback frames. Unsupported link types and
malformed frames produce coverage warnings.

Validation:

```text
python -m unittest discover -s tests -v
node tests/test_dashboard.js
python tests/browser_dashboard.py
```

Browser checks require Playwright plus Chromium/Edge and CDN access; they use
synthetic API responses to verify the UI, not real adapter capture.

## Workspace layout and extended indicators

Dashboard contains side-by-side upload/live inputs, the traffic assessment,
protocol explorer and overview charts. Analysis is a separate view with a
full-width connection graph, optional inspector, fullscreen mode and detailed
charts. The sidebar expands on hover/focus and can be toggled on touch screens.
Protocol cards filter connection evidence; ARP and some broadcast frames do not
produce Zeek connection nodes. Charts always describe the entire capture.

Display settings control graph layout, edge labels, chart visibility, top-N
results (up to 30), and time-bin grouping. Grouped rates are averaged over the
combined bin duration, rather than summing rates. Preferences last for the page
session. New charts show directional conversation bytes, destination ports,
private/public traffic direction, and DNS queries/replies/NXDOMAIN counts.
DNS errors are a subset of replies, not an additional disjoint packet category.

Extended detection defaults:

| Pattern | Default evidence threshold |
| --- | --- |
| TCP port scan | 20 distinct ports per source/target in a fixed minute |
| TCP host sweep | 20 hosts per source/port in a fixed minute |
| TCP resets | 50 resets and at least 20% of TCP packets |
| DNS name errors | 30 replies per client, at least 50% NXDOMAIN |
| DNS burst | 300 queries per client in a fixed minute |
| Long DNS names | 20 distinct names with a 50-character label or 100-character name |
| Large outbound transfer | 100 MB of captured frames from one RFC1918/ULA source to one global destination |
| Periodic TCP connections | 10 distinct SYN attempts; mean interval ≥5 seconds and variation ≤10% |
| Plaintext authorization | Complete HTTP request with Authorization/Proxy-Authorization; header value is never included in findings |

These thresholds are configurable in Settings (the reset/NXDOMAIN shares and
name-length/periodicity criteria are fixed). Retransmitted SYNs do not inflate
scan, sweep or periodicity counts. Fixed-minute boundaries can split bursts.
Periodicity uses the first 64 attempts. Extended tables are bounded to 20,000
keys each; truncation produces a coverage warning. Port/host/name sets stop at
the configured threshold and report counts as "at least". Large transfers,
regular polling, scanners, long DNS names and name errors can all be legitimate.

There is **no external threat-intelligence API** configured. Analysis uses local
FastAPI endpoints, Zeek and dpkt. Browser libraries/styles/fonts load from public
CDNs. Help shows whether the chart and graph libraries loaded. Live capture still
requires native Zeek/dumpcap and local access; it pauses between capture windows.
