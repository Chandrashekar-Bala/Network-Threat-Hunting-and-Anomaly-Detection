"""Explainable network behavior detections and risk scoring."""

from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

from nth_signal.config import DetectionConfig
from nth_signal.ingestion import FAIL_STATES, HIGH_RISK_PORTS, SUSPICIOUS_PORTS
from nth_signal.intel import match_flow
from nth_signal.mitre import mappings_for
from nth_signal.models import EvidenceRecord, Finding


RULES: dict[str, tuple[str, str, str, str, str]] = {
    "High risk destination port": ("NTH-NET-PORT-001", "Low", "Low", "service", "destination_port"),
    "Sensitive service exposed": ("NTH-NET-PORT-002", "Low", "Low", "service", "destination_port"),
    "Unsuccessful connection": ("NTH-NET-CONN-001", "Low", "Medium", "connection", "connection_state"),
    "Outbound volume outlier": ("NTH-NET-VOLUME-001", "Medium", "Medium", "volume", "byte_counts"),
    "Long lived flow": ("NTH-NET-DURATION-001", "Low", "Low", "duration", "flow_duration"),
    "Possible data staging or exfiltration": ("NTH-NET-EXFIL-001", "High", "Low", "volume", "byte_counts"),
    "Long DNS query name": ("NTH-DNS-LENGTH-001", "Medium", "Low", "dns", "dns_query"),
    "High entropy DNS label": ("NTH-DNS-ENTROPY-001", "Medium", "Low", "dns", "dns_query"),
    "Local threat feed match": ("NTH-IOC-MATCH-001", "Medium", "Low", "indicator", "ioc_match"),
    "Repeated connection failures": ("NTH-NET-FAIL-001", "Medium", "Medium", "connection", "failed_connections"),
    "Horizontal scan behavior": ("NTH-NET-SCAN-001", "High", "Medium", "scan", "unique_destinations"),
    "Vertical scan behavior": ("NTH-NET-SCAN-002", "High", "Medium", "scan", "unique_ports"),
    "Distributed probing pattern": ("NTH-NET-SCAN-003", "Medium", "Low", "scan", "unique_sources"),
    "Regular beacon pattern": ("NTH-NET-BEACON-001", "Medium", "Medium", "beacon", "connection_timing"),
}
CONFIDENCE_VALUES = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Very High": 4}
SEVERITY_VALUES = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def robust_outliers(
    values: list[float],
    floor: float,
    z_threshold: float = 4.5,
) -> set[int]:
    """Find unusually large values with a median/MAD baseline."""
    if len(values) < 8:
        return set()

    logged = [math.log1p(max(0.0, value)) for value in values]
    median = statistics.median(logged)
    mad = statistics.median(abs(value - median) for value in logged)

    if mad < 1e-9:
        # Many captures have a flat baseline. A high percentile is a useful
        # fallback, but the absolute floor still prevents tiny values firing.
        ordered = sorted(values)
        percentile_95 = ordered[min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1)]
        cutoff = max(floor, percentile_95)
        return {index for index, value in enumerate(values) if value >= cutoff and value > floor}

    robust_scale = 1.4826 * mad
    return {
        index
        for index, value in enumerate(logged)
        if (value - median) / robust_scale >= z_threshold and math.expm1(value) > floor
    }


def private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _window_candidates(
    indexes: list[int],
    flows: list[dict[str, Any]],
    window_seconds: float,
    threshold: int,
    unique_key: Callable[[int], str] | None = None,
) -> tuple[set[int], int, bool]:
    """Return flow indexes in time windows that cross an event/unique-value threshold."""
    timed = sorted(
        (flow["timestamp"], index)
        for index in indexes
        if (flow := flows[index]).get("timestamp") is not None
    )

    if not timed:
        unique_count = len({unique_key(index) for index in indexes}) if unique_key else len(indexes)
        if unique_count >= threshold:
            return set(indexes), unique_count, True
        return set(), 0, True

    ranges: list[tuple[int, int]] = []
    active_values: Counter[str] = Counter()
    left = 0
    largest_window = 0

    for right, (timestamp, index) in enumerate(timed):
        if unique_key:
            active_values[unique_key(index)] += 1

        while (timestamp - timed[left][0]).total_seconds() > window_seconds:
            if unique_key:
                old_key = unique_key(timed[left][1])
                active_values[old_key] -= 1
                if active_values[old_key] == 0:
                    del active_values[old_key]
            left += 1

        current_count = len(active_values) if unique_key else right - left + 1
        if current_count >= threshold:
            ranges.append((left, right))
            largest_window = max(largest_window, current_count)

    # Merge qualifying ranges, then convert their sorted positions back to flow IDs.
    hits: set[int] = set()
    if ranges:
        start, end = ranges[0]
        for next_start, next_end in ranges[1:]:
            if next_start <= end + 1:
                end = max(end, next_end)
            else:
                hits.update(index for _, index in timed[start:end + 1])
                start, end = next_start, next_end
        hits.update(index for _, index in timed[start:end + 1])
    return hits, largest_window, False


def _add_signal(
    flow: dict[str, Any],
    title: str,
    detail: str,
    weight: int,
    *,
    confidence: str | None = None,
    evidence_attributes: dict[str, Any] | None = None,
) -> None:
    if any(signal["title"] == title for signal in flow["signals"]):
        return
    rule_id, severity, default_confidence, group, evidence_type = RULES[title]
    observed_at = flow.get("timestamp")
    if isinstance(observed_at, datetime):
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=timezone.utc)
        observed_at = observed_at.astimezone(timezone.utc).isoformat()
    elif observed_at is not None:
        observed_at = str(observed_at)
    attributes = {
        "protocol": flow.get("protocol"),
        "source_port": flow.get("src_port"),
        "destination_port": flow.get("dst_port"),
        "bytes_sent": flow.get("src_bytes"),
        "bytes_received": flow.get("dst_bytes"),
    }
    attributes.update(evidence_attributes or {})
    evidence = EvidenceRecord(
        evidence_type=evidence_type,
        source="network flow telemetry",
        detail=detail,
        rule_id=rule_id,
        rule_version="1.0",
        observed_at=observed_at,
        flow_id=flow.get("id"),
        entities=[str(flow.get("src_ip", "")), str(flow.get("dst_ip", ""))],
        attributes=attributes,
    ).to_dict()
    flow["signals"].append({
        "rule_id": rule_id,
        "rule_version": "1.0",
        "title": title,
        "detail": detail,
        "weight": weight,
        "severity": severity,
        "confidence": confidence or default_confidence,
        "evidence_group": group,
        "evidence": [evidence],
    })


def _ioc_assessment(
    matches: list[dict[str, str]], config: DetectionConfig, assessed_at: datetime
) -> tuple[int, str, list[dict[str, str]]]:
    """Return a confidence- and freshness-aware IOC score and match context."""
    now = assessed_at
    confidence_factors = {
        label.casefold(): factor for label, factor in config.ioc_confidence_factors.items()
    }
    assessed = []
    for match in matches:
        confidence_values = [
            confidence_factors.get(label.strip().casefold(),
                confidence_factors.get("unspecified", 0.4))
            for label in match.get("confidence", "unspecified").split(" | ")
        ]
        confidence_factor = max(confidence_values, default=0.4)
        dates = [
            _parse_timestamp(value)
            for value in match.get("last_seen", "").split(" | ")
            if value.strip()
        ]
        expiries = [
            _parse_timestamp(value)
            for value in match.get("expires_at", "").split(" | ")
            if value.strip()
        ]
        freshness_factor = 1.0
        freshness = "Unknown"
        if dates:
            age_days = max(0.0, (now - max(dates)).total_seconds() / 86_400)
            freshness_factor = max(0.25, 1.0 - age_days / config.ioc_stale_after_days)
            freshness = "Fresh" if age_days <= config.ioc_stale_after_days else "Stale"
        if expiries and max(expiries) < now:
            freshness_factor = min(freshness_factor, 0.25)
            freshness = "Expired"
        source_count = len({item.strip() for item in match.get("source", "local feed").split(" | ") if item.strip()})
        provenance_factor = min(1.0, 0.75 + max(0, source_count - 1) * 0.1)
        points = round(config.ioc_score_cap * confidence_factor * freshness_factor * provenance_factor)
        confidence = _confidence_label(confidence_factor)
        if freshness in {"Stale", "Expired"}:
            confidence = "Low"
        assessed.append({
            **match,
            "freshness": freshness,
            "confidence_factor": f"{confidence_factor:.2f}",
            "freshness_factor": f"{freshness_factor:.2f}",
            "provenance_factor": f"{provenance_factor:.2f}",
            "source_count": str(source_count),
            "priority_points": str(points),
            "assessed_confidence": confidence,
            "assessed_at": now.isoformat(),
        })
    strongest = max(assessed, key=lambda item: int(item["priority_points"]), default=None)
    if strongest is None:
        return 0, "Low", assessed
    return int(strongest["priority_points"]), strongest["assessed_confidence"], assessed


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _confidence_label(value: float) -> str:
    if value >= 0.9:
        return "Very High"
    if value >= 0.75:
        return "High"
    if value >= 0.5:
        return "Medium"
    return "Low"


def analyze(
    flows: list[dict[str, Any]],
    config: DetectionConfig | None = None,
    iocs: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Add detections, evidence, ATT&CK candidates, and a priority score to flows."""
    config = config or DetectionConfig()
    config.validate()
    iocs = iocs or {}
    analysis_time = datetime.now(timezone.utc)
    high_risk_ports = {
        **HIGH_RISK_PORTS,
        **{int(port): description for port, description in config.high_risk_ports.items()},
    }
    sensitive_ports = {
        **SUSPICIOUS_PORTS,
        **{int(port): description for port, description in config.sensitive_ports.items()},
    }

    by_source: dict[str, list[int]] = defaultdict(list)
    by_destination_service: dict[tuple[str, int], list[int]] = defaultdict(list)
    beacon_groups: dict[tuple[str, str, int, str], list[int]] = defaultdict(list)
    failed_groups: dict[tuple[str, str, int], list[int]] = defaultdict(list)

    for index, flow in enumerate(flows):
        source = flow["src_ip"]
        destination = flow["dst_ip"]
        destination_port = flow["dst_port"]
        by_source[source].append(index)
        by_destination_service[(destination, destination_port)].append(index)
        beacon_groups[(source, destination, destination_port, flow["protocol"])].append(index)

        if flow["conn_state"].upper() in FAIL_STATES:
            failed_groups[(source, destination, destination_port)].append(index)

    hosts_seen = {flow["src_ip"] for flow in flows} | {flow["dst_ip"] for flow in flows}
    host_population = max(1, len(hosts_seen))
    outbound_outliers = robust_outliers(
        [flow["src_bytes"] for flow in flows],
        config.outbound_outlier_floor,
        config.outbound_robust_z,
    )
    long_flow_outliers = robust_outliers(
        [flow["duration"] for flow in flows],
        config.long_flow_seconds,
        config.outbound_robust_z,
    )

    for index, flow in enumerate(flows):
        port = flow["dst_port"]

        if port in high_risk_ports:
            _add_signal(
                flow,
                "High risk destination port",
                f"Port {port}: {high_risk_ports[port]}. A port number alone is not proof of malware.",
                24,
            )
        elif port in sensitive_ports and not private_ip(flow["dst_ip"]):
            _add_signal(
                flow,
                "Sensitive service exposed",
                f"Outbound connection to {sensitive_ports[port]} on port {port}.",
                12,
            )

        if flow["conn_state"].upper() in FAIL_STATES:
            _add_signal(
                flow,
                "Unsuccessful connection",
                f"Connection state {flow['conn_state']}; review nearby attempts and the destination service.",
                8,
            )

        if index in outbound_outliers:
            _add_signal(
                flow,
                "Outbound volume outlier",
                f"{flow['src_bytes']:,.0f} bytes sent; unusually high against this capture's baseline.",
                28,
            )
        if index in long_flow_outliers:
            _add_signal(
                flow,
                "Long lived flow",
                f"Flow duration of {flow['duration']:,.1f} seconds is unusually long in this capture.",
                12,
            )
        if (
            flow["src_bytes"] >= config.exfil_min_bytes
            and flow["src_bytes"] > max(1, flow["dst_bytes"]) * config.exfil_min_ratio
        ):
            _add_signal(
                flow,
                "Possible data staging or exfiltration",
                f"{flow['src_bytes'] / 1_000_000:.1f} MB sent versus {flow['dst_bytes'] / 1_000_000:.1f} MB received.",
                35,
            )

        dns_names = [*flow.get("dns_queries", [])]
        if flow.get("dns_query"):
            dns_names.append(flow["dns_query"])
        for name in dns_names:
            normalized = str(name).strip().rstrip(".").casefold()
            first_label = normalized.split(".", 1)[0]
            if len(normalized) >= config.dns_long_name_length:
                _add_signal(
                    flow,
                    "Long DNS query name",
                    f"DNS query is {len(normalized)} characters long: {normalized}.",
                    18,
                )
                break
            if len(first_label) >= 20 and shannon_entropy(first_label) >= config.dns_high_entropy_threshold:
                _add_signal(
                    flow,
                    "High entropy DNS label",
                    f"The first DNS label has elevated character entropy: {normalized}.",
                    22,
                )
                break

        matches = match_flow(flow, iocs)
        ioc_weight, ioc_confidence, matches = _ioc_assessment(matches, config, analysis_time)
        flow["ioc_matches"] = matches
        if matches:
            indicators = ", ".join(match["indicator"] for match in matches[:3])
            _add_signal(
                flow,
                "Local threat feed match",
                f"Matched {indicators} in the supplied local IOC list; confidence and freshness produce {ioc_weight} priority points.",
                ioc_weight,
                confidence=ioc_confidence,
                evidence_attributes={
                    "indicators": [match["indicator"] for match in matches],
                    "sources": [match.get("source", "local feed") for match in matches],
                    "freshness": [match.get("freshness", "Unknown") for match in matches],
                    "priority_points": ioc_weight,
                },
            )

    for (source, destination, port), indexes in failed_groups.items():
        hits, count, capture_only = _window_candidates(
            indexes,
            flows,
            config.failed_connection_window_seconds,
            config.failed_connection_threshold,
        )
        window = "across the capture" if capture_only else f"within {config.failed_connection_window_seconds:g} seconds"
        for index in hits:
            _add_signal(
                flows[index],
                "Repeated connection failures",
                f"{count} failed attempts to {destination}:{port} from {source} {window}.",
                22,
            )

    host_threshold = max(
        config.scan_unique_threshold,
        math.ceil(host_population * config.scan_host_fraction),
    )
    for source, indexes in by_source.items():
        host_hits, host_count, capture_only = _window_candidates(
            indexes,
            flows,
            config.scan_window_seconds,
            host_threshold,
            unique_key=lambda index: flows[index]["dst_ip"],
        )
        window = "across the capture" if capture_only else f"within {config.scan_window_seconds:g} seconds"
        for index in host_hits:
            _add_signal(
                flows[index],
                "Horizontal scan behavior",
                f"Source contacted at least {host_threshold} destination hosts {window} (up to {host_count}).",
                32,
            )

        port_hits, port_count, capture_only = _window_candidates(
            indexes,
            flows,
            config.scan_window_seconds,
            host_threshold,
            unique_key=lambda index: str(flows[index]["dst_port"]),
        )
        window = "across the capture" if capture_only else f"within {config.scan_window_seconds:g} seconds"
        for index in port_hits:
            _add_signal(
                flows[index],
                "Vertical scan behavior",
                f"Source attempted at least {host_threshold} destination ports {window} (up to {port_count}).",
                32,
            )

    distributed_threshold = max(
        config.distributed_source_threshold,
        math.ceil(host_population * config.distributed_host_fraction),
    )
    for (destination, port), indexes in by_destination_service.items():
        hits, source_count, capture_only = _window_candidates(
            indexes,
            flows,
            config.distributed_window_seconds,
            distributed_threshold,
            unique_key=lambda index: flows[index]["src_ip"],
        )
        window = "across the capture" if capture_only else f"within {config.distributed_window_seconds:g} seconds"
        for index in hits:
            _add_signal(
                flows[index],
                "Distributed probing pattern",
                f"At least {distributed_threshold} sources touched {destination}:{port} {window} (up to {source_count}).",
                20,
            )

    for (source, destination, port, protocol), indexes in beacon_groups.items():
        timed = sorted(
            (flows[index]["timestamp"], index)
            for index in indexes
            if flows[index].get("timestamp") is not None
        )
        if len(timed) < config.beacon_min_observations:
            continue

        gaps = [
            (timed[position][0] - timed[position - 1][0]).total_seconds()
            for position in range(1, len(timed))
        ]
        positive_gaps = [gap for gap in gaps if gap > 0]
        if len(positive_gaps) < config.beacon_min_observations - 1:
            continue

        average_gap = statistics.mean(positive_gaps)
        median_gap = statistics.median(positive_gaps)
        gap_variation = statistics.pstdev(positive_gaps) / average_gap if average_gap else 1
        if (
            config.beacon_min_interval_seconds <= median_gap <= config.beacon_max_interval_seconds
            and gap_variation <= config.beacon_max_gap_cv
        ):
            detail = (
                f"{len(timed)} {protocol} connections to {destination}:{port} at a median "
                f"{median_gap:.0f}s interval (gap variation {gap_variation:.0%})."
            )
            for _, index in timed:
                _add_signal(flows[index], "Regular beacon pattern", detail, 34)

    for index, flow in enumerate(flows):
        flow["analyzed_at"] = analysis_time.isoformat()
        flow["signals"] = [
            signal for signal in flow["signals"]
            if signal["title"] not in config.disabled_rules
        ]
        flow["mitre"] = mappings_for(flow["signals"])
        if not flow["signals"]:
            flow.update({"score": 0, "priority_score": 0, "severity": "Informational",
                         "confidence": "Low", "priority": "Informational", "finding": None})
            continue

        groups = {signal["evidence_group"] for signal in flow["signals"]}
        strongest_weight = max(signal["weight"] for signal in flow["signals"])
        corroboration = min(3, max(0, len(groups) - 1)) * config.corroboration_bonus
        priority_score = min(100, strongest_weight + corroboration)
        severity = max(
            (signal["severity"] for signal in flow["signals"]),
            key=lambda value: SEVERITY_VALUES[value],
        )
        confidence_values = [CONFIDENCE_VALUES[signal["confidence"]] for signal in flow["signals"]]
        confidence_value = max(confidence_values)
        if len(groups) >= 2 and confidence_value < CONFIDENCE_VALUES["Very High"]:
            confidence_value += 1
        confidence = next(label for label, value in CONFIDENCE_VALUES.items() if value == confidence_value)
        priority = _severity(priority_score, config)
        flow["score"] = priority_score  # Kept for consumers of the original JSON schema.
        flow["priority_score"] = priority_score
        flow["severity"] = severity
        flow["confidence"] = confidence
        flow["priority"] = priority
        title = max(flow["signals"], key=lambda signal: signal["weight"])["title"]
        finding = Finding(
            finding_id=f"NTH-FND-{index + 1:05d}",
            title=title,
            severity=severity,
            confidence=confidence,
            priority=priority,
            priority_score=priority_score,
            entities=sorted({str(flow.get("src_ip", "")), str(flow.get("dst_ip", ""))}),
            rule_ids=sorted({signal["rule_id"] for signal in flow["signals"]}),
            rule_versions={signal["rule_id"]: signal["rule_version"] for signal in flow["signals"]},
            evidence=[item for signal in flow["signals"] for item in signal["evidence"]],
            mitre_candidates=flow["mitre"],
            limitations=["Network telemetry alone cannot establish malicious intent."],
        )
        flow["finding"] = finding.to_dict()

    return flows


def _severity(score: int, config: DetectionConfig) -> str:
    if score >= config.critical_score:
        return "Critical"
    if score >= config.high_score:
        return "High"
    if score >= config.medium_score:
        return "Medium"
    if score:
        return "Low"
    return "Informational"


def shannon_entropy(value: str) -> float:
    """Measure character diversity; high entropy is a lead, not proof."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
