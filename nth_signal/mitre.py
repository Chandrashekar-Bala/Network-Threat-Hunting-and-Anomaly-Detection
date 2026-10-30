"""Conservative ATT&CK candidates for network-only observations."""

from __future__ import annotations

from typing import Any


TECHNIQUES = {
    "Horizontal scan behavior": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "confidence": "Behavior match",
        "evidence": (
            "One source contacted many distinct hosts, consistent with service discovery. "
            "Capture context is needed to separate authorized inventory from adversary activity."
        ),
    },
    "Vertical scan behavior": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "confidence": "Behavior match",
        "evidence": (
            "One source attempted many distinct destination ports, consistent with service "
            "enumeration. This does not identify the process or its intent."
        ),
    },
    "Distributed probing pattern": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "confidence": "Candidate",
        "evidence": (
            "Many sources touched the same host and port. Check asset roles and timing before "
            "treating this as coordinated discovery."
        ),
    },
    "Regular beacon pattern": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "confidence": "Candidate",
        "evidence": (
            "Regular connection timing can be consistent with command-and-control polling. "
            "Flow timing alone does not establish an application protocol or malicious channel."
        ),
    },
    "Possible data staging or exfiltration": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "confidence": "Candidate",
        "evidence": (
            "A large asymmetric outbound transfer is a lead only. Flow records do not show "
            "sensitive content, prior collection, or a C2 channel."
        ),
    },
    "High risk destination port": {
        "id": "T1571",
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1571/",
        "confidence": "Weak candidate",
        "evidence": (
            "This port is sometimes associated with suspicious tooling. The flow does not "
            "establish a protocol/port mismatch or adversary use."
        ),
    },
}


def mappings_for(signals: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Return one ATT&CK candidate per technique; leave unsupported signals unmapped."""
    mappings = []
    seen: set[str] = set()

    for signal in signals:
        technique = TECHNIQUES.get(signal.get("title"))
        if not technique or technique["id"] in seen:
            continue
        mappings.append({"signal": signal["title"], **technique})
        seen.add(technique["id"])

    return mappings
