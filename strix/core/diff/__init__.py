"""Semantic differential engine and volatile-field normalizer."""

from __future__ import annotations

from strix.core.diff.engine import diff
from strix.core.diff.models import (
    AuthSignalDelta,
    BodyStructureDelta,
    Candidate,
    CandidateKind,
    DiffResult,
    NormalizedResponse,
    SemanticDelta,
    SetCookieDelta,
)
from strix.core.diff.normalize import normalize_response, status_class


__all__ = [
    "AuthSignalDelta",
    "BodyStructureDelta",
    "Candidate",
    "CandidateKind",
    "DiffResult",
    "NormalizedResponse",
    "SemanticDelta",
    "SetCookieDelta",
    "diff",
    "normalize_response",
    "status_class",
]
