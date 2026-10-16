"""Simple manual entry point: python test.py capture.pcap [--output result.json]."""

import argparse
import json
from pathlib import Path
import sys

from pcap_story import AnalysisConfig, ZeekError, get_flowchart


def main():
    parser = argparse.ArgumentParser(description="Convert a PCAP into an evidence-backed story graph")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--output", type=Path, help="Create a JSON file; refuses to overwrite existing files")
    parser.add_argument("--runtime", choices=("native", "wsl"), default="native")
    parser.add_argument("--distribution", help="WSL distribution containing Zeek")
    parser.add_argument("--zeek-binary", default="zeek")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--ignore-checksums", action="store_true")
    args = parser.parse_args()
    try:
        if args.output is not None and args.output.exists():
            raise FileExistsError(f"Refusing to overwrite existing output: {args.output}")
        result = get_flowchart(args.pcap, config=AnalysisConfig(
            runtime=args.runtime, wsl_distribution=args.distribution,
            zeek_binary=args.zeek_binary, timeout_seconds=args.timeout,
            ignore_checksums=args.ignore_checksums,
        ))
        encoded = json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False)
        if args.output:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(encoded + "\n")
        else:
            print(encoded)
        return 0
    except (OSError, ValueError, KeyError, ZeekError) as exc:
        print(f"Analysis failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
