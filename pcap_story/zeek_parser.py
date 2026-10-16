"""Line-oriented JSON and standard tab-separated Zeek log parsing."""

import json
import math
from pathlib import Path

LOG_NAMES = ("conn", "dns", "ssl", "http")


def _reject_constant(value):
    raise ValueError(f"Non-finite JSON number: {value}")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite JSON number")
    return number


def _convert(value, kind, empty, unset, set_separator):
    if value == unset:
        return None
    if value == empty:
        return [] if kind.startswith(("set[", "vector[")) else ""
    if kind.startswith(("set[", "vector[")):
        return [_convert(item, kind[kind.index("[") + 1:-1], empty, unset, set_separator)
                for item in value.split(set_separator)]
    if kind in {"count", "int", "port"}:
        return int(value)
    if kind in {"time", "interval", "double"}:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("Non-finite Zeek number")
        return number
    if kind == "bool":
        if value not in {"T", "F"}:
            raise ValueError("Invalid Zeek boolean")
        return value == "T"
    # Zeek encodes special characters as literal \\xNN sequences in TSV.
    import re
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), value)


def read_log(path: Path):
    separator, set_separator, empty, unset = "\t", ",", "(empty)", "-"
    fields, kinds = [], []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            line = raw.rstrip("\r\n")
            if not line:
                continue
            try:
                if line.startswith("#separator "):
                    separator = bytes(line.split(" ", 1)[1], "ascii").decode("unicode_escape")
                elif line.startswith("#"):
                    key, _, value = line.partition(separator)
                    if key == "#fields":
                        fields = value.split(separator)
                    elif key == "#types":
                        kinds = value.split(separator)
                    elif key == "#set_separator":
                        set_separator = value
                    elif key == "#empty_field":
                        empty = value
                    elif key == "#unset_field":
                        unset = value
                elif line.lstrip().startswith("{"):
                    record = json.loads(line, parse_constant=_reject_constant, parse_float=_finite_float)
                    if not isinstance(record, dict):
                        raise ValueError("Expected a JSON object")
                    yield record
                else:
                    values = line.split(separator)
                    if not fields or len(fields) != len(kinds) or len(values) != len(fields):
                        raise ValueError("Missing TSV headers or mismatched field count")
                    yield dict(zip(fields, (
                        _convert(v, k, empty, unset, set_separator) for v, k in zip(values, kinds)
                    )))
            except (ValueError, TypeError, UnicodeError) as exc:
                raise ValueError(f"{path.name}:{line_number}: {exc}") from exc


def parse_zeek_logs(directory: Path) -> dict[str, list[dict]]:
    return {name: list(read_log(directory / f"{name}.log"))
            if (directory / f"{name}.log").is_file() else [] for name in LOG_NAMES}
