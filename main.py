import os
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from collections import Counter
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Depends
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool
import dpkt
from pcap_story import AnalysisConfig, ZeekError, get_flowchart
from pcap_story.live_capture import capture_window, list_interfaces, capture_status
from pcap_story.packet_analytics import analyze_packets, SecuritySettings

app = FastAPI(title="NetFlow Analyzer API")


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).with_name("dashboard.html"),
                        headers={"Cache-Control": "no-store, max-age=0"})


@app.get("/dashboard-ui.js", include_in_schema=False)
def dashboard_script():
    return FileResponse(Path(__file__).with_name("dashboard-ui.js"), media_type="text/javascript",
                        headers={"Cache-Control": "no-store, max-age=0"})


def analyze_upload(file, ignore_checksums=False, thresholds=None):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(400, "Upload a .pcap, .pcapng, or .cap capture.")
    try:
        config = AnalysisConfig(
            runtime=os.getenv("PCAP_ZEEK_RUNTIME", "native"),
            wsl_distribution=os.getenv("PCAP_ZEEK_DISTRIBUTION") or None,
            zeek_binary=os.getenv("PCAP_ZEEK_BINARY", "zeek"),
            timeout_seconds=float(os.getenv("PCAP_ZEEK_TIMEOUT", "600")),
            ignore_checksums=ignore_checksums,
        )
    except ValueError as exc:
        raise HTTPException(503, "Invalid server Zeek configuration.") from exc
    try:
        with tempfile.TemporaryDirectory(prefix="pcap_upload_") as directory:
            capture = Path(directory) / ("capture" + suffix)
            with capture.open("wb") as destination:
                size = 0
                while chunk := file.file.read(1024 * 1024):
                    size += len(chunk)
                    if size > 500 * 1024 * 1024:
                        raise HTTPException(413, "Capture exceeds the 500 MB upload limit.")
                    destination.write(chunk)
            result = get_flowchart(capture, config=config)
            result["analytics"] = analyze_packets(capture, thresholds)
            result["summary"]["pcap"] = (file.filename or "capture").replace("\\", "/").rsplit("/", 1)[-1]
            return result
    except ZeekError as exc:
        cause = exc.__cause__
        status = 504 if isinstance(cause, subprocess.TimeoutExpired) else (
            503 if isinstance(cause, OSError) or "WSL" in str(exc) else 502
        )
        raise HTTPException(status, str(exc)) from exc
    except (ValueError, dpkt.UnpackError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(500, "Could not read or process the uploaded capture.") from exc


@app.post("/api/flowchart")
async def flowchart(file: UploadFile = File(...), settings: str = Form("{}")):
    try:
        try:
            thresholds = SecuritySettings.model_validate_json(settings)
        except ValueError as exc:
            raise HTTPException(422, "Invalid detection settings.") from exc
        return await run_in_threadpool(analyze_upload, file, thresholds=thresholds)
    finally:
        await file.close()


def require_local_capture(request: Request):
    """Capture controls are available only to a local, same-origin dashboard."""
    allowed = {"127.0.0.1", "::1", "localhost"}
    if not request.client or request.client.host not in allowed:
        raise HTTPException(403, "Live capture is available only on the server's local machine.")
    if request.url.hostname not in allowed:
        raise HTTPException(403, "Open the dashboard through localhost or 127.0.0.1.")
    origin = request.headers.get("origin")
    if origin and origin != f"{request.url.scheme}://{request.url.netloc}":
        raise HTTPException(403, "Live capture requires a same-origin request.")


class LiveCaptureRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=512)
    seconds: int = Field(default=10, ge=5, le=60, strict=True)
    capture_filter: str = Field(default="", max_length=512, pattern=r"^[^\x00\r\n]*$")
    settings: SecuritySettings = Field(default_factory=SecuritySettings)


@app.get("/api/live/interfaces", dependencies=[Depends(require_local_capture)])
def live_interfaces():
    return {"interfaces": list_interfaces()}


@app.get("/api/live/status", dependencies=[Depends(require_local_capture)])
def live_status():
    return capture_status()


@app.post("/api/live/capture", dependencies=[Depends(require_local_capture)])
def live_capture(options: LiveCaptureRequest):
    with capture_window(options.interface, options.seconds, options.capture_filter) as path:
        with path.open("rb") as source:
            result = analyze_upload(UploadFile(filename="live.pcap", file=source),
                                    ignore_checksums=True, thresholds=options.settings)
        result["summary"]["capture_mode"] = "live_window"
        result["summary"]["interface"] = options.interface
        result["summary"]["warnings"].append(
            "Latest capture window only; traffic during analysis is not captured. "
            "Connections spanning windows may have incomplete evidence. "
            "Each window stops at its duration, 25 MB, or 100,000 packets. "
            "Checksum validation is disabled for local adapter offload."
        )
        return result

# Allow requests from your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def parse_pcap_stats(file_path: str):
    """Parses PCAP file using dpkt and returns a structured dictionary."""
    total_packets = 0
    total_bytes = 0
    proto_counts = Counter()
    src_ip_counts = Counter()
    dst_ip_counts = Counter()

    with open(file_path, "rb") as f:
        # Detect standard PCAP vs PCAPNG
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            total_packets += 1
            total_bytes += len(buf)

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            # Check if payload contains an IPv4 or IPv6 packet
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                src_ip_counts[src_ip] += 1
                dst_ip_counts[dst_ip] += 1

                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    proto_counts["TCP"] += 1
                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    proto_counts["UDP"] += 1
                elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                    proto_counts["ICMP"] += 1
                else:
                    proto_counts["Other IP"] += 1

            elif isinstance(eth.data, dpkt.ip6.IP6):
                proto_counts["IPv6"] += 1
            elif isinstance(eth.data, dpkt.arp.ARP):
                proto_counts["ARP"] += 1
            else:
                proto_counts["Other"] += 1

    return {
        "summary": {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "size_mb": round(total_bytes / (1024 * 1024), 2)
        },
        "protocols": dict(proto_counts),
        "top_sources": dict(src_ip_counts.most_common(5)),
        "top_destinations": dict(dst_ip_counts.most_common(5))
    }

@app.post("/api/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    # 1. Validate file extension
    valid_extensions = (".pcap", ".cap")
    if not file.filename.lower().endswith(valid_extensions):
        raise HTTPException(
            status_code=400, 
            detail="Unsupported file format. Please upload a .pcap file."
        )

    # 2. Define safe temporary storage path on Windows
    temp_dir = os.path.join(os.getcwd(), "temp_uploads")
    os.makedirs(temp_dir, exist_ok=True)
    temp_file_path = os.path.join(temp_dir, file.filename)

    try:
        # 3. Stream the uploaded file to disk
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # 4. Run dpkt analysis
        analysis_data = parse_pcap_stats(temp_file_path)

        return {
            "status": "success",
            "filename": file.filename,
            "data": analysis_data
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Parsing error: {str(e)}")

    finally:
        # 5. Clean up temporary file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
