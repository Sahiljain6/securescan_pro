from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class HttpObservation:
    stage: str
    status_code: int
    body: str
    headers: dict[str, str]
    url: str
    duration_ms: float


@dataclass
class ValidationTrace:
    baseline_capture: dict[str, Any]
    non_destructive_probe: dict[str, Any]
    error_normalization: dict[str, Any]
    behavioral_delta: dict[str, Any]
    correlated_evidence_scoring: dict[str, Any]


@dataclass
class DomainAssessment:
    domain: str
    summary: str
    evidence: list[dict[str, Any]]
    trace: ValidationTrace
    mitigation_signals: dict[str, Any]
    confidence: float = 0.0
    risk: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanSession:
    target_url: str
    observations: dict[str, HttpObservation]
    shared_context: dict[str, Any]
