"""Small, JSON-friendly records shared by detections and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class EvidenceRecord:
    """One observation that explains why a rule produced a signal."""

    evidence_type: str
    source: str
    detail: str
    rule_id: str
    rule_version: str
    observed_at: str | None = None
    flow_id: str | int | None = None
    entities: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    """Analyst-facing summary for one flow and its supporting rule evidence."""

    finding_id: str
    title: str
    severity: str
    confidence: str
    priority: str
    priority_score: int
    entities: list[str]
    rule_ids: list[str]
    rule_versions: dict[str, str]
    evidence: list[dict[str, Any]]
    mitre_candidates: list[dict[str, str]]
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
