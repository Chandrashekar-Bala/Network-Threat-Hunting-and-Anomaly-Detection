"""Local IOC list loading and exact IP/domain matching.

No external lookups are made. This keeps private telemetry on the analyst's
machine and makes every match traceable to the supplied feed.
"""

from __future__ import annotations

import csv
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_iocs(path: Path) -> dict[str, dict[str, str]]:
    """Read a CSV with indicator,type,source,confidence,notes and optional dates."""
    iocs: dict[str, dict[str, str]] = {}
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise ValueError("IOC file needs a CSV header row.")
        names = {name.strip().casefold(): name for name in reader.fieldnames if name}
        if "indicator" not in names:
            raise ValueError("IOC CSV needs an 'indicator' column.")
        for line_number, row in enumerate(reader, 2):
            value = (row.get(names["indicator"]) or "").strip().casefold().rstrip(".")
            if not value or value.startswith("#"):
                continue
            kind = (row.get(names.get("type", "")) or "").strip().casefold()
            address = None
            try:
                address = ipaddress.ip_address(value)
                value = str(address)
                actual_kind = "ip"
            except ValueError:
                try:
                    value = value.encode("idna").decode("ascii")
                except UnicodeError:
                    raise ValueError(f"Invalid IOC on line {line_number}: {value!r}") from None
                if not _valid_domain(value):
                    raise ValueError(f"Invalid IOC on line {line_number}: {value!r}")
                actual_kind = "domain"
            accepted_types = {"ip", "ipv4", "ipv6", "ip-address"} if actual_kind == "ip" else {"domain", "hostname", "fqdn"}
            if kind and kind not in accepted_types:
                raise ValueError(f"IOC type does not match indicator on line {line_number}: {kind!r}")
            if kind == "ipv4" and address and address.version != 4:
                raise ValueError(f"IOC on line {line_number} is not an IPv4 address.")
            if kind == "ipv6" and address and address.version != 6:
                raise ValueError(f"IOC on line {line_number} is not an IPv6 address.")
            entry = {
                "indicator": value,
                "type": actual_kind,
                "source": (row.get(names.get("source", "")) or "local feed").strip() or "local feed",
                "confidence": (row.get(names.get("confidence", "")) or "unspecified").strip() or "unspecified",
                "notes": (row.get(names.get("notes", "")) or "").strip(),
                "last_seen": _normalize_timestamp(row.get(names.get("last_seen", "")), "last_seen", line_number),
                "expires_at": _normalize_timestamp(row.get(names.get("expires_at", "")), "expires_at", line_number),
            }
            if value in iocs:
                for field in ("source", "confidence", "notes", "last_seen", "expires_at"):
                    values = [*iocs[value][field].split(" | "), *entry[field].split(" | ")]
                    iocs[value][field] = " | ".join(dict.fromkeys(item for item in values if item))
            else:
                iocs[value] = entry
    return iocs


def _normalize_timestamp(value: str | None, field: str, line_number: int) -> str:
    """Validate optional feed timestamps and store them in a consistent form."""
    value = (value or "").strip()
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid {field} timestamp on IOC line {line_number}: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _valid_domain(value: str) -> bool:
    if len(value) > 253 or "." not in value:
        return False
    try:
        encoded = value.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = encoded.split(".")
    valid_labels = all(
        0 < len(label) <= 63
        and label[0] != "-"
        and label[-1] != "-"
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )
    has_valid_suffix = any(character.isalpha() for character in labels[-1])
    return valid_labels and has_valid_suffix


def match_flow(flow: dict[str, Any], iocs: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    """Match either endpoint IP or an exact/subdomain DNS query."""
    candidates = [flow.get("src_ip", ""), flow.get("dst_ip", "")]
    candidates.extend(str(query).strip().casefold().rstrip(".") for query in flow.get("dns_queries", []))
    query = str(flow.get("dns_query", "")).strip().casefold().rstrip(".")
    if query:
        candidates.append(query)
    matches = []
    matched: set[str] = set()
    seen_candidates: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen_candidates:
            continue
        seen_candidates.add(candidate)
        if candidate in iocs:
            matches.append(iocs[candidate])
            matched.add(candidate)
            continue
        labels = candidate.split(".")
        for index in range(1, len(labels)):
            parent_domain = ".".join(labels[index:])
            detail = iocs.get(parent_domain)
            if detail and detail["type"] == "domain" and parent_domain not in matched:
                matches.append(detail)
                matched.add(parent_domain)
    return matches
