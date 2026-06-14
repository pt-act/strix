"""Locked output shapes for the differential engine."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


CandidateKind = Literal["IDOR", "BFLA", "expired_authorized"]
AuthSignalDelta = Literal["none", "gained_access", "lost_access"]
BodyStructureDelta = Literal["same", "shape_changed", "size_changed"]
SetCookieDelta = Literal["none", "session_set", "session_cleared"]


class NormalizedResponse(BaseModel):
    """A response with volatile fields canonicalized."""

    status_code: int
    status_class: str
    headers: dict[str, str]
    body: str
    body_length: int
    set_cookie_names: list[str]
    normalized_fields: list[str]

    model_config = {"extra": "forbid"}


class StatusClassDelta(BaseModel):
    a: str
    b: str

    model_config = {"extra": "forbid"}


class SemanticDelta(BaseModel):
    """Per-pair semantic comparison result."""

    pair: tuple[str, str]
    status_class_delta: StatusClassDelta | None
    body_structure_delta: BodyStructureDelta
    normalized_length_delta: int
    auth_signal_delta: AuthSignalDelta = "none"
    set_cookie_delta: SetCookieDelta = "none"
    normalized: bool

    model_config = {"extra": "forbid"}


class Candidate(BaseModel):
    """A flagged access-control anomaly."""

    kind: CandidateKind
    pair: tuple[str, str]
    rationale: str
    evidence_class: Literal["diff"] = "diff"

    model_config = {"extra": "forbid"}


class DiffResult(BaseModel):
    """Complete output of the differential engine."""

    deltas: list[SemanticDelta]
    candidates: list[Candidate]

    model_config = {"extra": "forbid"}
