from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    title: str
    value: str
    module: str
    confidence: float
    explanation: str
    verified: bool = False


@dataclass
class SolverRun:
    module: str
    status: str
    duration_ms: float
    detail: str = ""


@dataclass
class AnalysisResult:
    challenge_name: str
    input_sha256: str
    input_summary: str
    categories: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    runs: list[SolverRun] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
