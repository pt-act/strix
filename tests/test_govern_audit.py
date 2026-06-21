"""Tests for strix.core.govern.audit — SGL-S6.

SP10: every governance decision ⇒ exactly one audit entry; replayable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.govern.audit import (
    AuditAction,
    AuditEntry,
    AuditLog,
    read_audit_log,
)

# ══════════════════════════════════════════════════════════════════════════════
# TG5 — Focused tests
# ══════════════════════════════════════════════════════════════════════════════


class TestAuditLogRecord:
    """TG5.1 — basic record and replay."""

    def test_record_and_replay(self) -> None:
        log = AuditLog(engagement_id="test-001")
        log.record(AuditAction.ALLOW, target="example.com", reason="scope_match")
        log.record(AuditAction.DENY, target="evil.com", reason="out_of_scope")

        entries = log.replay()
        assert len(entries) == 2
        assert entries[0].action == AuditAction.ALLOW
        assert entries[0].target == "example.com"
        assert entries[1].action == AuditAction.DENY
        assert entries[1].target == "evil.com"

    def test_engagement_id_propagated(self) -> None:
        log = AuditLog(engagement_id="eng-42")
        entry = log.record(AuditAction.HALT, target="*", reason="cost_ceiling")
        assert entry.engagement_id == "eng-42"

    def test_agent_id_recorded(self) -> None:
        log = AuditLog()
        entry = log.record(
            AuditAction.DENY,
            target="evil.com",
            reason="out_of_scope",
            agent_id="agent-abc",
        )
        assert entry.agent_id == "agent-abc"

    def test_metadata_recorded(self) -> None:
        log = AuditLog()
        entry = log.record(
            AuditAction.HALT,
            target="*",
            reason="cost_ceiling",
            metadata={"tokens_used": 5_000_000},
        )
        assert entry.metadata["tokens_used"] == 5_000_000

    def test_timestamps_monotonically_increasing(self) -> None:
        log = AuditLog()
        e1 = log.record(AuditAction.ALLOW, target="a.com", reason="r1")
        e2 = log.record(AuditAction.DENY, target="b.com", reason="r2")
        assert e2.timestamp >= e1.timestamp
        assert e2.wall_time >= e1.wall_time


class TestAuditLogCount:
    """TG5.2 — counting and grouping."""

    def test_count(self) -> None:
        log = AuditLog()
        log.record(AuditAction.ALLOW, target="a.com", reason="r")
        log.record(AuditAction.DENY, target="b.com", reason="r")
        log.record(AuditAction.HALT, target="*", reason="r")
        assert log.count() == 3

    def test_count_by_action(self) -> None:
        log = AuditLog()
        log.record(AuditAction.ALLOW, target="a.com", reason="r")
        log.record(AuditAction.ALLOW, target="b.com", reason="r")
        log.record(AuditAction.DENY, target="c.com", reason="r")
        counts = log.count_by_action()
        assert counts["allow"] == 2
        assert counts["deny"] == 1

    def test_clear(self) -> None:
        log = AuditLog()
        log.record(AuditAction.ALLOW, target="a.com", reason="r")
        assert log.count() == 1
        log.clear()
        assert log.count() == 0


class TestAuditLogPersistence:
    """TG5.3 — file persistence and replay reader."""

    def test_flush_and_read(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log = AuditLog(engagement_id="test", log_path=log_path, )
        # Force low threshold for testing
        log._flush_threshold = 3

        log.record(AuditAction.ALLOW, target="a.com", reason="r1")
        log.record(AuditAction.DENY, target="b.com", reason="r2")
        log.record(AuditAction.HALT, target="*", reason="r3")

        # Should have auto-flushed at threshold
        assert log_path.exists()
        entries = read_audit_log(log_path)
        assert len(entries) == 3
        assert entries[0].action == AuditAction.ALLOW
        assert entries[2].action == AuditAction.HALT

    def test_manual_flush(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log = AuditLog(log_path=log_path)
        log.record(AuditAction.ALLOW, target="a.com", reason="r1")
        log.flush()

        entries = read_audit_log(log_path)
        assert len(entries) == 1

    def test_read_nonexistent_file(self, tmp_path: Path) -> None:
        entries = read_audit_log(tmp_path / "nonexistent.jsonl")
        assert entries == []

    def test_read_malformed_lines_skipped(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(
            '{"not": "valid"}\n'
            '{"timestamp":1.0,"wall_time":1.0,"action":"allow","target":"a.com","reason":"r","metadata":{}}\n',
            encoding="utf-8",
        )
        entries = read_audit_log(log_path)
        assert len(entries) == 1  # malformed line skipped


class TestAuditEntryModel:
    """TG5.4 — model validation."""

    def test_entry_roundtrip(self) -> None:
        entry = AuditEntry(
            timestamp=1.0,
            wall_time=1000.0,
            action=AuditAction.ALLOW,
            target="example.com",
            reason="scope_match",
            agent_id="agent-1",
            engagement_id="eng-1",
            metadata={"key": "value"},
        )
        data = entry.model_dump()
        restored = AuditEntry(**data)
        assert restored == entry

    def test_entry_json_serialisable(self) -> None:
        entry = AuditEntry(
            timestamp=1.0,
            wall_time=1000.0,
            action=AuditAction.DENY,
            target="evil.com",
            reason="out_of_scope",
            metadata={},
        )
        json_str = entry.model_dump_json()
        restored = AuditEntry.model_validate_json(json_str)
        assert restored.target == "evil.com"


# ══════════════════════════════════════════════════════════════════════════════
# SP10 — PBT: every decision ⇒ exactly one audit entry; replayable
# ══════════════════════════════════════════════════════════════════════════════

_actions_st = st.sampled_from(list(AuditAction))
_targets_st = st.from_regex(r"[a-z][a-z0-9-]{0,8}\.(com|net|io)", fullmatch=True)
_reasons_st = st.from_regex(r"[a-z_]{3,15}", fullmatch=True)


@given(st.lists(st.tuples(_actions_st, _targets_st, _reasons_st), min_size=1, max_size=50))
@settings(max_examples=200)
def test_sp10_one_entry_per_decision(
    decisions: list[tuple[AuditAction, str, str]],
) -> None:
    """SP10: each record() call produces exactly one entry; replay is ordered."""
    log = AuditLog(engagement_id="sp10-test")

    for action, target, reason in decisions:
        log.record(action, target=target, reason=reason)

    entries = log.replay()
    assert len(entries) == len(decisions), (
        f"Expected {len(decisions)} entries, got {len(entries)}"
    )

    # Every entry has a unique monotonic timestamp (or equal)
    for i in range(1, len(entries)):
        assert entries[i].timestamp >= entries[i - 1].timestamp

    # Actions match input order
    for entry, (action, target, reason) in zip(entries, decisions):
        assert entry.action == action
        assert entry.target == target
        assert entry.reason == reason


@given(st.lists(st.tuples(_actions_st, _targets_st, _reasons_st), min_size=1, max_size=30))
@settings(max_examples=100)
def test_sp10_persistence_roundtrip(
    decisions: list[tuple[AuditAction, str, str]],
) -> None:
    """SP10: persisted entries survive a file roundtrip."""
    import tempfile
    tmp_dir = Path(tempfile.mkdtemp())
    log_path = tmp_dir / "audit.jsonl"
    log = AuditLog(log_path=log_path)
    log._flush_threshold = len(decisions)  # force flush at end

    for action, target, reason in decisions:
        log.record(action, target=target, reason=reason)
    log.flush()

    restored = read_audit_log(log_path)
    assert len(restored) == len(decisions)

    for entry, (action, target, reason) in zip(restored, decisions):
        assert entry.action == action
        assert entry.target == target
        assert entry.reason == reason
