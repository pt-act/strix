"""Semantic differential engine for response comparison."""

from __future__ import annotations

from typing import Any

from strix.core.diff.models import (
    AuthSignalDelta,
    BodyStructureDelta,
    Candidate,
    DiffResult,
    NormalizedResponse,
    SemanticDelta,
    SetCookieDelta,
    StatusClassDelta,
)
from strix.core.diff.normalize import normalize_response


_ROLE_ORDER = {"anonymous": 0, "user": 1, "admin": 2, "expired": -1}


def _body_structure(a: NormalizedResponse, b: NormalizedResponse) -> BodyStructureDelta:
    if a.body == b.body:
        return "same"
    if a.body_length != b.body_length:
        return "size_changed"
    return "shape_changed"


def _auth_signal(
    a: NormalizedResponse,
    b: NormalizedResponse,
) -> AuthSignalDelta:
    a_ok = a.status_class == "2xx"
    b_ok = b.status_class == "2xx"
    a_denied = a.status_class in {"4xx", "5xx"}
    b_denied = b.status_class in {"4xx", "5xx"}
    if a_denied and b_ok:
        return "gained_access"
    if a_ok and b_denied:
        return "lost_access"
    return "none"


def _set_cookie_delta(
    a: NormalizedResponse,
    b: NormalizedResponse,
) -> SetCookieDelta:
    a_names = set(a.set_cookie_names)
    b_names = set(b.set_cookie_names)
    if not a_names and b_names:
        return "session_set"
    if a_names and not b_names:
        return "session_cleared"
    return "none"


def _diff_pair(
    label_a: str,
    response_a: NormalizedResponse,
    label_b: str,
    response_b: NormalizedResponse,
) -> SemanticDelta:
    structure = _body_structure(response_a, response_b)
    auth_signal_value = _auth_signal(response_a, response_b)
    status_delta: StatusClassDelta | None = None
    if response_a.status_class != response_b.status_class:
        status_delta = StatusClassDelta(a=response_a.status_class, b=response_b.status_class)
    return SemanticDelta(
        pair=(label_a, label_b),
        status_class_delta=status_delta,
        body_structure_delta=structure,
        normalized_length_delta=abs(response_a.body_length - response_b.body_length),
        auth_signal_delta=auth_signal_value,
        set_cookie_delta=_set_cookie_delta(response_a, response_b),
        normalized=True,
    )


def _role_rank(label: str) -> int:
    return _ROLE_ORDER.get(label, 1)


def _is_success(response: NormalizedResponse) -> bool:
    return response.status_class == "2xx"


def _is_denied(response: NormalizedResponse) -> bool:
    return response.status_class in {"4xx", "5xx"}


def _is_expired_authorized(
    delta: SemanticDelta,
    responses: dict[str, NormalizedResponse],
) -> bool:
    a, b = delta.pair
    if "expired" not in (a, b):
        return False
    expired_label = a if a == "expired" else b
    other = b if a == "expired" else a
    return _is_success(responses[expired_label]) and _is_denied(responses[other])


def _is_bfla(
    delta: SemanticDelta,
    responses: dict[str, NormalizedResponse],
) -> bool:
    a, b = delta.pair
    rank_a = _role_rank(a)
    rank_b = _role_rank(b)
    lower, higher = (a, b) if rank_a < rank_b else (b, a)
    return (
        higher == "admin"
        and lower in {"user", "anonymous"}
        and _is_success(responses[lower])
        and _is_denied(responses[higher])
    )


def _flag_candidates(
    deltas: list[SemanticDelta],
    responses: dict[str, NormalizedResponse],
) -> list[Candidate]:
    """Flag IDOR / BFLA / expired_authorized candidates from deltas."""
    candidates: list[Candidate] = []

    # Expired authorization: the expired identity itself succeeds (2xx) while a
    # valid identity is denied. That is the violation, not the other way around.
    for delta in deltas:
        if not _is_expired_authorized(delta, responses):
            continue
        a, b = delta.pair
        other = b if a == "expired" else a
        candidates.append(
            Candidate(
                kind="expired_authorized",
                pair=("expired", other),
                rationale=(
                    "Expired session received a successful response while "
                    f"{other} was denied, indicating stale authorization is still accepted."
                ),
                evidence_class="diff",
            )
        )

    # BFLA: a lower-priv role succeeds at an admin-gated function while admin is denied.
    # The violation is the lower identity accessing the endpoint, not the admin gaining access.
    for delta in deltas:
        if not _is_bfla(delta, responses):
            continue
        a, b = delta.pair
        rank_a = _role_rank(a)
        rank_b = _role_rank(b)
        lower, higher = (a, b) if rank_a < rank_b else (b, a)
        candidates.append(
            Candidate(
                kind="BFLA",
                pair=(lower, higher),
                rationale=(
                    f"{lower} succeeded at an admin-gated endpoint while {higher} was denied."
                ),
                evidence_class="diff",
            )
        )

    # IDOR: two different non-anonymous identities both succeed with the same body.
    for delta in deltas:
        a, b = delta.pair
        if a in {"anonymous", "expired"} or b in {"anonymous", "expired"}:
            continue
        if delta.auth_signal_delta != "none":
            continue
        response_a = responses[a]
        response_b = responses[b]
        if not (_is_success(response_a) and _is_success(response_b)):
            continue
        if delta.body_structure_delta == "same":
            candidates.append(
                Candidate(
                    kind="IDOR",
                    pair=(a, b),
                    rationale=(
                        f"{a} and {b} both received the same response for a "
                        f"resource, suggesting cross-role access to one resource."
                    ),
                    evidence_class="diff",
                )
            )

    # Deduplicate by (kind, pair) preserving order.
    seen: set[tuple[str, tuple[str, str]]] = set()
    deduped: list[Candidate] = []
    for candidate in candidates:
        key = (candidate.kind, candidate.pair)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def diff(
    responses: list[dict[str, Any]],
    axis: str = "identity",
) -> DiffResult:
    """Compute semantic deltas across a set of labeled responses.

    Args:
        responses: List of ``{"label": str, "response": {...}}`` dicts.
        axis: Axis label for the diff (e.g. ``identity``).

    Returns:
        A ``DiffResult`` with pairwise deltas and flagged candidates.
    """
    _ = axis
    labeled: list[tuple[str, NormalizedResponse]] = []
    for item in responses:
        label = str(item.get("label", ""))
        raw_response: dict[str, Any] = item.get("response") or {}
        normalized = normalize_response(raw_response)
        labeled.append((label, normalized))

    deltas: list[SemanticDelta] = []
    for i in range(len(labeled)):
        for j in range(i + 1, len(labeled)):
            label_a, response_a = labeled[i]
            label_b, response_b = labeled[j]
            deltas.append(_diff_pair(label_a, response_a, label_b, response_b))

    responses_by_label = dict(labeled)
    candidates = _flag_candidates(deltas, responses_by_label)
    return DiffResult(deltas=deltas, candidates=candidates)
