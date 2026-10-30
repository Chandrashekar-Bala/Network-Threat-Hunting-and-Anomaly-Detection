"""Detection thresholds and JSON configuration loading."""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

RULE_NAMES = {
    "High risk destination port",
    "Sensitive service exposed",
    "Unsuccessful connection",
    "Outbound volume outlier",
    "Long lived flow",
    "Possible data staging or exfiltration",
    "Long DNS query name",
    "High entropy DNS label",
    "Local threat feed match",
    "Repeated connection failures",
    "Horizontal scan behavior",
    "Vertical scan behavior",
    "Distributed probing pattern",
    "Regular beacon pattern",
}


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds can be tuned per environment without editing detection code."""

    outbound_outlier_floor: int = 100_000
    outbound_robust_z: float = 4.5
    long_flow_seconds: float = 120.0
    exfil_min_bytes: int = 10_000_000
    exfil_min_ratio: float = 5.0
    scan_unique_threshold: int = 15
    scan_host_fraction: float = 0.08
    scan_window_seconds: float = 60.0
    distributed_source_threshold: int = 20
    distributed_host_fraction: float = 0.12
    distributed_window_seconds: float = 300.0
    failed_connection_threshold: int = 10
    failed_connection_window_seconds: float = 60.0
    high_risk_ports: dict[str, str] = field(default_factory=dict)
    sensitive_ports: dict[str, str] = field(default_factory=dict)
    disabled_rules: list[str] = field(default_factory=list)
    beacon_min_observations: int = 6
    beacon_min_interval_seconds: float = 10.0
    beacon_max_interval_seconds: float = 3_600.0
    beacon_max_gap_cv: float = 0.15
    dns_long_name_length: int = 50
    dns_high_entropy_threshold: float = 3.7
    critical_score: int = 75
    high_score: int = 50
    medium_score: int = 25
    ioc_score_cap: int = 36
    ioc_stale_after_days: int = 90
    corroboration_bonus: int = 7
    ioc_confidence_factors: dict[str, float] = field(default_factory=lambda: {
        "low": 0.35,
        "medium": 0.60,
        "high": 0.85,
        "confirmed": 1.0,
        "unspecified": 0.40,
    })

    def validate(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            expected = type(item.default)
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError(f"Configuration value '{item.name}' must be finite.")
            if expected is int and (isinstance(value, bool) or not isinstance(value, int)):
                raise ValueError(f"Configuration value '{item.name}' must be an integer.")
            if expected is float and (isinstance(value, bool) or not isinstance(value, (int, float))):
                raise ValueError(f"Configuration value '{item.name}' must be a number.")
        positive_fields = (
            "outbound_outlier_floor", "outbound_robust_z", "long_flow_seconds",
            "exfil_min_bytes", "exfil_min_ratio", "scan_unique_threshold",
            "scan_window_seconds", "distributed_source_threshold",
            "distributed_window_seconds", "failed_connection_threshold",
            "failed_connection_window_seconds", "beacon_min_observations",
            "beacon_min_interval_seconds", "beacon_max_interval_seconds",
            "dns_long_name_length", "dns_high_entropy_threshold", "critical_score",
            "high_score", "medium_score", "ioc_score_cap", "ioc_stale_after_days",
        )
        for name in positive_fields:
            if getattr(self, name) <= 0:
                raise ValueError(f"Configuration value '{name}' must be greater than zero.")
        for name in ("high_risk_ports", "sensitive_ports"):
            ports = getattr(self, name)
            if not isinstance(ports, dict):
                raise ValueError(f"Configuration value '{name}' must be a JSON object of port names and descriptions.")
            for port, description in ports.items():
                try:
                    number = int(port)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"Port key '{port}' in '{name}' must be an integer from 1 to 65535.") from exc
                if not 1 <= number <= 65_535 or not isinstance(description, str) or not description.strip():
                    raise ValueError(f"Each '{name}' entry needs a port from 1 to 65535 and a description.")
        if not isinstance(self.disabled_rules, list) or any(not isinstance(rule, str) for rule in self.disabled_rules):
            raise ValueError("'disabled_rules' must be a list of rule names.")
        unknown_rules = sorted(set(self.disabled_rules) - RULE_NAMES)
        if unknown_rules:
            raise ValueError(f"Unknown rule name(s): {', '.join(unknown_rules)}")
        if not 0 < self.scan_host_fraction <= 1:
            raise ValueError("'scan_host_fraction' must be greater than 0 and at most 1.")
        if not 0 < self.distributed_host_fraction <= 1:
            raise ValueError("'distributed_host_fraction' must be greater than 0 and at most 1.")
        if not 0 <= self.beacon_max_gap_cv <= 1:
            raise ValueError("'beacon_max_gap_cv' must be between 0 and 1.")
        if self.beacon_min_interval_seconds > self.beacon_max_interval_seconds:
            raise ValueError("Beacon minimum interval cannot exceed its maximum interval.")
        if not self.critical_score > self.high_score > self.medium_score:
            raise ValueError("Risk score thresholds must descend: critical > high > medium.")
        if self.ioc_score_cap > 100 or self.ioc_score_cap >= self.critical_score:
            raise ValueError("'ioc_score_cap' must be at most 100 and below the critical score threshold.")
        if not 0 <= self.corroboration_bonus <= 25:
            raise ValueError("'corroboration_bonus' must be between 0 and 25.")
        if not isinstance(self.ioc_confidence_factors, dict) or not self.ioc_confidence_factors:
            raise ValueError("'ioc_confidence_factors' must be a non-empty JSON object.")
        for label, factor in self.ioc_confidence_factors.items():
            if (not isinstance(label, str) or not label.strip()
                    or isinstance(factor, bool) or not isinstance(factor, (int, float))
                    or not math.isfinite(factor) or not 0 <= factor <= 1):
                raise ValueError("IOC confidence factors need named values between 0 and 1.")

    @classmethod
    def from_file(cls, path: Path) -> "DetectionConfig":
        try:
            values: Any = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in configuration file: {exc}") from exc
        if not isinstance(values, dict):
            raise ValueError("Configuration file must contain a JSON object.")
        allowed = {item.name for item in fields(cls)}
        unknown = sorted(set(values) - allowed)
        if unknown:
            raise ValueError(f"Unknown configuration option(s): {', '.join(unknown)}")
        config = cls(**values)
        config.validate()
        return config

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_default_config(path: Path) -> None:
    """Write the current defaults as a readable JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(DetectionConfig().to_dict(), indent=2) + "\n", encoding="utf-8")
