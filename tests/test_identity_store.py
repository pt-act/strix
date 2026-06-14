"""Tier-1 and Tier-2 tests for the per-target identity store."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest import TestCase

from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.identity import (
    Freshness,
    Identity,
    IdentityStore,
    redact_identity,
)
from strix.core.identity.store import identity_store_path


_ALPHANUMERIC = st.characters(whitelist_categories=("L", "N"))
_SAFE_TEXT = st.text(min_size=1, max_size=32, alphabet=_ALPHANUMERIC)


def _make_identity(
    target_key: str,
    role: str,
    *,
    cookies: dict[str, str] | None = None,
    tokens: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    provenance: str = "proxy_capture",
) -> Identity:
    return Identity(
        target_key=target_key,
        role=role,
        cookies=cookies or {},
        tokens=tokens or {},
        headers=headers or {},
        provenance=provenance,  # type: ignore[arg-type]
        freshness=Freshness(captured_at=datetime.now(UTC).isoformat(), status="fresh"),
    )


class TestIdentityStoreTier1(TestCase):
    """Focused behaviour tests for the SQLite-backed identity store."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()
        self.store = IdentityStore(identity_store_path(self.run_dir))

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_crud_and_restart_persistence_round_trip(self) -> None:
        identity = _make_identity(
            "example.com:443",
            "user",
            cookies={"session": "abc123"},
            tokens={"authorization": "Bearer user-token"},
        )
        self.store.upsert_identity(identity)

        # Re-open the store to verify durability.
        self.store.close()
        self.store = IdentityStore(identity_store_path(self.run_dir))
        loaded = self.store.get_identity("example.com:443", "user")
        assert loaded is not None
        self.assertEqual(loaded.cookies, {"session": "abc123"})
        self.assertEqual(loaded.tokens, {"authorization": "Bearer user-token"})
        self.assertTrue(loaded.is_authorized())

    def test_same_role_write_dedupes(self) -> None:
        self.store.upsert_identity(
            _make_identity("example.com:443", "user", tokens={"authorization": "Bearer old"})
        )
        self.store.upsert_identity(
            _make_identity("example.com:443", "user", tokens={"authorization": "Bearer new"})
        )
        identities = self.store.list_identities("example.com:443")
        user_identities = [i for i in identities if i.role == "user"]
        self.assertEqual(len(user_identities), 1)
        self.assertEqual(
            user_identities[0].tokens["authorization"],
            "Bearer new",
        )

    def test_expired_always_present_and_never_authorized(self) -> None:
        identities = self.store.list_identities("example.com:443")
        expired = next((i for i in identities if i.role == "expired"), None)
        assert expired is not None
        self.assertTrue(expired.is_reserved_expired)
        self.assertFalse(expired.is_authorized())
        # Deleting the expired role must not remove it.
        self.assertFalse(self.store.delete_identity("example.com:443", "expired"))
        identities_after = self.store.list_identities("example.com:443")
        self.assertIn("expired", [i.role for i in identities_after])


class TestIdentityStoreTier2PBT(TestCase):
    """Property-based security invariants for the identity store."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()
        self.store = IdentityStore(identity_store_path(self.run_dir))

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    @given(
        target_key=_SAFE_TEXT,
        role=st.sampled_from(["user", "admin"]),
        cookie_value=_SAFE_TEXT,
        token_value=_SAFE_TEXT,
    )
    @settings(max_examples=50, deadline=None)
    def test_credential_scoping(
        self,
        target_key: str,
        role: str,
        cookie_value: str,
        token_value: str,
    ) -> None:
        identity = _make_identity(
            target_key,
            role,
            cookies={"session": cookie_value},
            tokens={"authorization": f"Bearer {token_value}"},
        )
        self.store.upsert_identity(identity)

        # No cross-target read: a different target only sees its own expired identity.
        other_target = f"{target_key}-other"
        other_identities = self.store.list_identities(other_target)
        self.assertEqual([i.role for i in other_identities], ["expired"])

        # Redaction masks credential values in all agent-facing summaries.
        redacted = redact_identity(identity)
        self.assertEqual(redacted["cookies"]["session"], "****")
        self.assertEqual(redacted["tokens"]["authorization"], "****")
        # No credential value appears unmasked in the redacted credential fields.
        redacted_values = set(redacted["cookies"].values()) | set(redacted["tokens"].values())
        self.assertNotIn(cookie_value, redacted_values)
        self.assertNotIn(token_value, redacted_values)
        self.assertNotIn(f"Bearer {token_value}", redacted_values)

    @given(
        target_key=_SAFE_TEXT,
    )
    @settings(max_examples=20, deadline=None)
    def test_expired_session_safety(self, target_key: str) -> None:
        identities = self.store.list_identities(target_key)
        expired = next((i for i in identities if i.role == "expired"), None)
        assert expired is not None
        self.assertFalse(expired.is_authorized())
        # A manually marked-expired identity is also never authorized.
        stale = _make_identity(target_key, "user")
        stale.freshness.status = "expired"
        self.store.upsert_identity(stale)
        loaded = self.store.get_identity(target_key, "user")
        assert loaded is not None
        self.assertFalse(loaded.is_authorized())


if __name__ == "__main__":
    import unittest

    unittest.main()
