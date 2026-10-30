"""Read CSV, TSV, and Zeek connection logs into a consistent flow format."""

from __future__ import annotations

import csv
import ipaddress
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FIELD_ALIASES = {
    "timestamp": ("timestamp", "ts", "time", "starttime", "start_time", "datetime", "date"),
    "src_ip": ("src_ip", "srcip", "source_ip", "sourceip", "id.orig_h", "orig_h", "src", "source"),
    "dst_ip": ("dst_ip", "dstip", "dest_ip", "destination_ip", "destinationip", "id.resp_h", "resp_h", "dst", "destination"),
    "src_port": ("src_port", "srcport", "source_port", "id.orig_p", "orig_p"),
    "dst_port": ("dst_port", "dstport", "dest_port", "destination_port", "id.resp_p", "resp_p", "port"),
    "protocol": ("protocol", "proto", "ip_proto"),
    "service": ("service", "app_proto", "application"),
    "dns_query": ("dns_query", "query", "qname", "domain", "domain_name", "hostname"),
    "duration": ("duration", "dur", "flow_duration", "duration_sec"),
    "src_bytes": ("src_bytes", "orig_bytes", "source_bytes", "bytes_out", "sent_bytes", "bytes_sent", "total_length_of_fwd_packets", "fwd_bytes"),
    "dst_bytes": ("dst_bytes", "resp_bytes", "destination_bytes", "bytes_in", "received_bytes", "bytes_received", "total_length_of_bwd_packets", "bwd_bytes"),
    "src_packets": ("src_packets", "orig_pkts", "source_packets", "packets_out", "total_fwd_packets", "total_forward_packets"),
    "dst_packets": ("dst_packets", "resp_pkts", "destination_packets", "packets_in", "total_backward_packets", "total_bwd_packets"),
    "conn_state": ("conn_state", "state", "connection_state", "connstate"),
}

FIELD_LOOKUP = {
    re.sub(r"[^a-z0-9]", "", alias.casefold()): field
    for field, aliases in FIELD_ALIASES.items()
    for alias in aliases
}

HIGH_RISK_PORTS = {
    4444: "commonly used by reverse shells",
    5555: "sometimes used by command channels",
    6667: "IRC",
    1337: "high port sometimes used by implants",
    31337: "historical backdoor port",
    9001: "Tor ORPort; context dependent",
}

SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    1433: "MS SQL",
    3389: "RDP",
    5900: "VNC",
    8081: "alternate web service",
    8443: "alternate TLS service",
}

FAILED_STATES = {"S0", "REJ", "RSTO", "RSTR", "SH", "SHR", "OTH", "TIMEOUT", "FAILED", "FAIL", "DENY"}
FAIL_STATES = FAILED_STATES  # Compatibility for earlier releases.


def _field_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _number(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or str(value).strip() in {"", "-", "(empty)", "None", "nan"}:
            return default
        result = float(value)
        return result if math.isfinite(result) else default
    except (TypeError, ValueError):
        return default


def _port(value: Any) -> int:
    parsed = _number(value, -1)
    if not parsed.is_integer() or not 0 <= parsed <= 65_535:
        return 0
    return int(parsed)


def normalize_ip(value: Any) -> str:
    """Return a canonical address, or an empty string if the value is invalid."""
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def parse_time(value: Any) -> datetime | None:
    """Read an ISO timestamp or Unix timestamp and return UTC."""
    text = str(value or "").strip()
    if not text or text in {"-", "(empty)"}:
        return None

    try:
        seconds = float(text)
        if math.isfinite(seconds):
            return datetime.fromtimestamp(seconds, timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _read_zeek(path: Path) -> list[dict[str, str]]:
    fields: list[str] | None = None
    rows: list[dict[str, str]] = []

    with path.open("r", encoding="utf-8-sig", errors="replace") as stream:
        for line_number, line in enumerate(stream, 1):
            line = line.rstrip("\r\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if not line or line.startswith("#"):
                continue
            if fields is None:
                raise ValueError("Zeek log is missing its #fields header.")
            values = line.split("\t")
            if len(values) != len(fields):
                raise ValueError(f"Zeek row {line_number} has {len(values)} values; expected {len(fields)}.")
            rows.append(dict(zip(fields, values)))

    if not fields:
        raise ValueError("This looks like a Zeek log, but it has no #fields header.")
    return rows


def read_flows(path: Path) -> tuple[list[dict[str, Any]], str]:
    """Read a delimited file or Zeek log and normalize recognized columns."""
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        first_line = stream.readline()
        stream.seek(0)
        is_zeek = first_line.startswith("#") and (
            "#fields" in first_line or "#separator" in first_line
        )

        if is_zeek:
            raw_rows = _read_zeek(path)
            source_format = "Zeek log"
        else:
            sample = stream.read(8192)
            stream.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel
            reader = csv.DictReader(stream, dialect=dialect)
            if not reader.fieldnames:
                raise ValueError("The input file is empty or has no header row.")
            raw_rows = list(reader)
            source_format = "Delimited flow export"

    flows: list[dict[str, Any]] = []
    for row_number, raw in enumerate(raw_rows, 1):
        normalized = {
            FIELD_LOOKUP.get(_field_key(name), _field_key(name)): value
            for name, value in raw.items()
            if name is not None
        }
        source_ip = normalize_ip(normalized.get("src_ip"))
        destination_ip = normalize_ip(normalized.get("dst_ip"))
        if not source_ip or not destination_ip:
            continue

        dns_query = str(normalized.get("dns_query", "")).strip().casefold().rstrip(".")
        if dns_query in {"-", "(empty)"}:
            dns_query = ""

        flows.append({
            "id": row_number,
            "timestamp": parse_time(normalized.get("timestamp")),
            "src_ip": source_ip,
            "dst_ip": destination_ip,
            "src_port": _port(normalized.get("src_port")),
            "dst_port": _port(normalized.get("dst_port")),
            "protocol": str(normalized.get("protocol", "unknown")).strip().upper() or "UNKNOWN",
            "service": str(normalized.get("service", "")).strip(),
            "dns_query": dns_query,
            "dns_queries": [],
            "duration": max(0.0, _number(normalized.get("duration"))),
            "src_bytes": max(0.0, _number(normalized.get("src_bytes"))),
            "dst_bytes": max(0.0, _number(normalized.get("dst_bytes"))),
            "src_packets": max(0.0, _number(normalized.get("src_packets"))),
            "dst_packets": max(0.0, _number(normalized.get("dst_packets"))),
            "conn_state": str(normalized.get("conn_state", "")).strip().upper() or "—",
            "signals": [],
            "score": 0,
        })

    if not flows:
        raise ValueError("No valid flows found. Check that source and destination IP columns are present.")
    return flows, source_format


# Keep the old public name available for scripts that imported it directly.
read_zeek = _read_zeek
