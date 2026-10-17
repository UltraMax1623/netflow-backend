# PCAP story analysis package

This new package is independent of the existing FastAPI backend. Existing files,
including `main.py`, `requirements.txt`, and `dashboard.html`, are unchanged.
The package itself uses Python's standard library only (Python 3.10+).

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

## Output contract, version 1.0

Top-level keys:

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
`dpkt` can be added later for independent capture-wide statistics and packet
references without double-counting Zeek flows.

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

Run `python -m pip install -r requirements.txt`, then `python -m uvicorn main:app --reload` from the repository root. Open http://127.0.0.1:8000 and upload a .pcap, .pcapng, or .cap capture. Section 4 shows real analysis; other analytics are labeled demo data. Internet access is required for the pinned Cytoscape 3.30.4 and existing styling/chart CDNs.

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
