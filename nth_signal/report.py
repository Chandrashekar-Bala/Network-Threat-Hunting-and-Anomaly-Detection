"""Sample capture data and standalone HTML report generation."""

from __future__ import annotations

import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


APP_NAME = "NTH // SIGNAL"


def _flow(
    flow_id: int,
    timestamp: datetime,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    protocol: str,
    sent_bytes: int,
    received_bytes: int,
    duration: float,
) -> dict[str, Any]:
    return {
        "id": flow_id,
        "timestamp": timestamp,
        "src_ip": source_ip,
        "dst_ip": destination_ip,
        "src_port": source_port,
        "dst_port": destination_port,
        "protocol": protocol,
        "service": "",
        "dns_query": "",
        "dns_queries": [],
        "duration": duration,
        "src_bytes": sent_bytes,
        "dst_bytes": received_bytes,
        "src_packets": 4,
        "dst_packets": 3,
        "conn_state": "SF",
        "signals": [],
        "score": 0,
    }


def demo_flows() -> list[dict[str, Any]]:
    """Build a repeatable synthetic capture for a quick dashboard tour."""
    generator = random.Random(21)
    capture_start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=3)
    internal_hosts = [f"10.10.4.{host}" for host in range(10, 34)]
    outside_hosts = [
        "10.10.8.12",
        "10.10.8.15",
        "198.51.100.27",
        "203.0.113.61",
        "10.10.8.90",
    ]
    common_ports = [443, 443, 443, 53, 80, 445, 3389, 22]
    flows = []

    for flow_id in range(1, 96):
        source_ip = generator.choice(internal_hosts)
        destination_ip = generator.choice(outside_hosts)
        destination_port = generator.choice(common_ports)
        protocol = "UDP" if destination_port == 53 else "TCP"
        flows.append(_flow(
            flow_id=flow_id,
            timestamp=capture_start + timedelta(seconds=generator.randint(0, 10_000)),
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=generator.randint(42_000, 62_000),
            destination_port=destination_port,
            protocol=protocol,
            sent_bytes=generator.randint(200, 15_000),
            received_bytes=generator.randint(200, 80_000),
            duration=round(generator.random() * 8, 2),
        ))

    # Repeated connections provide a clear beaconing example.
    for attempt in range(8):
        flows.append(_flow(
            flow_id=96 + attempt,
            timestamp=capture_start + timedelta(minutes=15 * attempt),
            source_ip="10.10.4.77",
            destination_ip="198.51.100.27",
            source_port=51_400 + attempt,
            destination_port=4444,
            protocol="TCP",
            sent_bytes=1_200,
            received_bytes=640,
            duration=2.4,
        ))

    # A large outbound transfer provides a separate volume investigation lead.
    flows.append(_flow(
        flow_id=104,
        timestamp=capture_start + timedelta(hours=2, minutes=47),
        source_ip="10.10.4.91",
        destination_ip="203.0.113.61",
        source_port=53_121,
        destination_port=443,
        protocol="TCP",
        sent_bytes=48_000_000,
        received_bytes=700_000,
        duration=484,
    ))
    return flows


def report_payload(
    flows: list[dict[str, Any]],
    source: str,
    source_format: str,
    critical_threshold: int = 75,
) -> dict[str, Any]:
    timestamps = [flow["timestamp"] for flow in flows if flow.get("timestamp")]
    findings = [flow for flow in flows if flow.get("signals")]
    signal_counts = Counter(
        signal["title"]
        for flow in flows
        for signal in flow.get("signals", [])
    )
    hosts = {
        address
        for flow in flows
        for address in (flow["src_ip"], flow["dst_ip"])
    }

    summary = {
        "app": APP_NAME,
        "source": source,
        "format": source_format,
        "created": (
            flows[0].get("analyzed_at", datetime.now(timezone.utc).isoformat())
            if flows else datetime.now(timezone.utc).isoformat()
        ),
        "flow_count": len(flows),
        "host_count": len(hosts),
        "incident_count": len(findings),
        "critical_count": sum(flow.get("priority") == "Critical" for flow in findings),
        "critical_threshold": critical_threshold,
        "severity_counts": dict(Counter(flow.get("severity", "Informational") for flow in findings)),
        "confidence_counts": dict(Counter(flow.get("confidence", "Low") for flow in findings)),
        "priority_counts": dict(Counter(flow.get("priority", "Informational") for flow in findings)),
        "ioc_match_count": sum(len(flow.get("ioc_matches", [])) for flow in flows),
        "time_start": min(timestamps).isoformat() if timestamps else None,
        "time_end": max(timestamps).isoformat() if timestamps else None,
        "signal_counts": signal_counts.most_common(),
    }
    serializable_flows = [
        {
            **flow,
            "timestamp": flow["timestamp"].isoformat() if flow.get("timestamp") else None,
        }
        for flow in flows
    ]
    serializable_findings = [flow["finding"] for flow in serializable_flows if flow.get("finding")]
    return {"meta": summary, "flows": serializable_flows, "findings": serializable_findings}


def render_html(data: dict[str, Any]) -> str:
    """Fill the self-contained report template with safely encoded flow data."""
    safe_json = (
        json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    template_path = Path(__file__).with_name("report_template.html")
    template = template_path.read_text(encoding="utf-8")
    return template.replace("__NTH_REPORT_DATA__", safe_json)
