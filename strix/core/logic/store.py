"""Durable per-engagement store for the agent-proposed business-logic model."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003
from typing import Any, Self

from strix.core.logic.models import BusinessLogicModel


class BusinessLogicStore:
    """SQLite-backed store for one engagement's business-logic model.

    The store is scoped to a single engagement; it never reads or writes data
    for another engagement, satisfying the per-engagement scope requirement.
    """

    _TABLE = """
        CREATE TABLE IF NOT EXISTS logic_model (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id TEXT NOT NULL,
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(self._TABLE)

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

    def save(self, model: BusinessLogicModel) -> None:
        """Persist the full business-logic model, replacing any existing row."""
        payload = model.model_dump_json()
        with self._conn:
            self._conn.execute(
                "DELETE FROM logic_model WHERE engagement_id = ?",
                (model.engagement_id,),
            )
            self._conn.execute(
                "INSERT INTO logic_model (engagement_id, payload, updated_at) VALUES (?, ?, ?)",
                (model.engagement_id, payload, self._now()),
            )

    def load(self, engagement_id: str) -> BusinessLogicModel | None:
        """Load the business-logic model for this engagement, or None if absent."""
        row = self._conn.execute(
            "SELECT payload FROM logic_model WHERE engagement_id = ? ORDER BY id DESC LIMIT 1",
            (engagement_id,),
        ).fetchone()
        if row is None:
            return None
        return BusinessLogicModel.model_validate_json(row[0])

    def merge(self, model: BusinessLogicModel) -> BusinessLogicModel:
        """Merge a new model into the stored one by keyed collections."""
        existing = self.load(model.engagement_id)
        if existing is None:
            self.save(model)
            return model

        merged = BusinessLogicModel(
            engagement_id=model.engagement_id,
            target_id=model.target_id or existing.target_id,
            journeys={**existing.journeys, **model.journeys},
            lifecycles={**existing.lifecycles, **model.lifecycles},
            trust_boundaries={**existing.trust_boundaries, **model.trust_boundaries},
            monetary_operations={**existing.monetary_operations, **model.monetary_operations},
            flows={**existing.flows, **model.flows},
        )
        self.save(merged)
        return merged

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class BusinessLogicResultStore:
    """SQLite-backed store for business-logic violation results."""

    _TABLE = """
        CREATE TABLE IF NOT EXISTS logic_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            result_id TEXT NOT NULL UNIQUE,
            engagement_id TEXT NOT NULL,
            flow_name TEXT NOT NULL,
            invariant_kind TEXT NOT NULL,
            verdict TEXT NOT NULL,
            reason TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(self._TABLE)

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

    def save(
        self,
        result_id: str,
        engagement_id: str,
        flow_name: str,
        invariant_kind: str,
        verdict: str,
        reason: str,
        payload: dict[str, Any],
    ) -> None:
        """Persist a gated violation result."""
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO logic_results (
                    result_id, engagement_id, flow_name, invariant_kind,
                    verdict, reason, payload, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result_id,
                    engagement_id,
                    flow_name,
                    invariant_kind,
                    verdict,
                    reason,
                    json.dumps(payload, default=str),
                    self._now(),
                ),
            )

    def load(self, result_id: str) -> dict[str, Any] | None:
        """Load a result by its id."""
        row = self._conn.execute(
            "SELECT payload FROM logic_results WHERE result_id = ?",
            (result_id,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])  # type: ignore[no-any-return]

    def list_for_flow(self, engagement_id: str, flow_name: str) -> list[dict[str, Any]]:
        """List results for a flow, newest first."""
        rows = self._conn.execute(
            """
            SELECT payload FROM logic_results
            WHERE engagement_id = ? AND flow_name = ?
            ORDER BY id DESC
            """,
            (engagement_id, flow_name),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
