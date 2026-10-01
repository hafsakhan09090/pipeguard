"""Shared data model for all PipeGuard scanners."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict, field

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.lower(), 0)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str            # info | low | medium | high | critical
    category: str            # secret | sast | dependency
    file: str
    line: int
    snippet: str = ""
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    confidence: str = "medium"   # low | medium | high
    extra: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable ID used for de-duplication and baselining.

        Deliberately excludes the line number so a finding keeps the same
        fingerprint when unrelated code above it is edited.
        """
        raw = "|".join([self.rule_id, self.file, self.snippet.strip()])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def score(self) -> int:
        """Triage score: severity weight x confidence multiplier (0-100)."""
        base = {"info": 5, "low": 25, "medium": 50, "high": 75, "critical": 95}
        mult = {"low": 0.7, "medium": 0.85, "high": 1.0}
        return round(base.get(self.severity, 0) * mult.get(self.confidence, 0.85))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        d["score"] = self.score
        return d
