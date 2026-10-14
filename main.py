import os
import shutil
import socket
from collections import Counter
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import dpkt

app = FastAPI(title="NetFlow Analyzer API")

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