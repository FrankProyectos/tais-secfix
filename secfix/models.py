"""Estructuras de datos compartidas por el pipeline."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class Finding:
    rule_id: str
    path: str
    line: int
    end_line: int
    message: str
    cwe: str
    severity: str
    code: str = ""
    trace: str = ""
    # completado por el triage
    verdict: Optional[str] = None          # "TP" | "FP" | None (sin LLM)
    confidence: Optional[float] = None
    justification: str = ""
    group_id: Optional[str] = None

    @property
    def short_rule(self) -> str:
        return self.rule_id.split(".")[-1]

    def fingerprint(self) -> str:
        raw = f"{self.short_rule}|{self.path}|{self.code.strip()}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]


@dataclass
class Validation:
    v1_compiles: Optional[bool] = None
    v2_sast_clean: Optional[bool] = None
    v3_tests: Optional[bool] = None
    v4_exploit_blocked: Optional[bool] = None
    details: list = field(default_factory=list)

    @property
    def passed(self) -> bool:
        checks = [self.v1_compiles, self.v2_sast_clean, self.v3_tests, self.v4_exploit_blocked]
        return all(c is not False for c in checks) and self.v1_compiles is True and self.v2_sast_clean is True


@dataclass
class RepairGroup:
    """Hallazgos verdaderos positivos que caen en la misma función: se reparan juntos."""
    group_id: str
    path: str
    start: int            # primera línea (incluye decoradores)
    end: int              # última línea
    original_code: str
    findings: list = field(default_factory=list)
    fixed_code: Optional[str] = None
    explanation: str = ""
    attempts: int = 0
    accepted: bool = False
    validation: Optional[Validation] = None
    history: list = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["findings"] = [f.fingerprint() for f in self.findings]
        return d
