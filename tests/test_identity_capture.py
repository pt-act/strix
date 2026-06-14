"""Tier-1 tests for identity capture and import/export."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import TestCase

from strix.core.identity import IdentityStore
from strix.core.identity.capture import capture_from_login, capture_from_proxy
from strix.core.identity.export import (
    export_identities,
    export_identities_to_file,
    import_identities,
    import_identities_from_file,
)
from strix.core.identity.store import identity_store_path


class TestIdentityCaptureTier1(TestCase):
    """Focused behaviour tests for capture and import/export."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()
        self.store = IdentityStore(identity_store_path(self.run_dir))

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_proxy_capture_stores_labelled_redacted_identity(self) -> None:
        identity = capture_from_proxy(
            "example.com:443",
            "admin",
            method="GET",
            url="https://example.com:443/api/users",
            headers={
                "Cookie": "session=admin-session-123",
                "Authorization": "Bearer admin-token",
                "X-Api-Key": "secret-api-key",
                "Content-Type": "application/json",
            },
            body="{}",
        )
        self.store.upsert_identity(identity)
        loaded = self.store.get_identity("example.com:443", "admin")
        assert loaded is not None
        self.assertEqual(loaded.cookies, {"session": "admin-session-123"})
        self.assertEqual(loaded.tokens, {"authorization": "Bearer admin-token"})
        self.assertEqual(loaded.headers, {"X-Api-Key": "secret-api-key"})
        self.assertEqual(loaded.provenance, "proxy_capture")
        self.assertTrue(loaded.is_authorized())

    def test_login_flow_capture_harvests_post_login_auth(self) -> None:
        identity = capture_from_login(
            "example.com:443",
            "user",
            response_headers={
                "Authorization": "Bearer user-token",
                "Set-Cookie": "session=user-session-456; Path=/; HttpOnly",
            },
            response_cookies={"session": "user-session-456"},
            response_body=None,
        )
        self.store.upsert_identity(identity)
        loaded = self.store.get_identity("example.com:443", "user")
        assert loaded is not None
        self.assertEqual(loaded.tokens, {"authorization": "Bearer user-token"})
        self.assertEqual(loaded.cookies, {"session": "user-session-456"})
        self.assertEqual(loaded.provenance, "login_flow")

    def test_export_import_round_trip_preserves_credentials(self) -> None:
        identity = capture_from_proxy(
            "example.com:443",
            "user",
            method="GET",
            url="https://example.com:443/api/account",
            headers={
                "Cookie": "session=roundtrip-session",
                "Authorization": "Bearer roundtrip-token",
            },
            body="",
        )
        self.store.upsert_identity(identity)
        identities = self.store.list_identities("example.com:443")
        artifact = export_identities("example.com:443", identities)
        reloaded = import_identities(artifact, expected_target_key="example.com:443")

        for i in reloaded:
            self.store.upsert_identity(i)
        final = self.store.get_identity("example.com:443", "user")
        assert final is not None
        self.assertEqual(final.cookies, {"session": "roundtrip-session"})
        self.assertEqual(final.tokens, {"authorization": "Bearer roundtrip-token"})

    def test_import_rejects_foreign_target_key(self) -> None:
        artifact = export_identities(
            "foreign.example.com",
            [
                capture_from_proxy(
                    "foreign.example.com",
                    "user",
                    method="GET",
                    url="https://foreign.example.com/api",
                    headers={"Authorization": "Bearer foreign-token"},
                    body="",
                )
            ],
        )
        with self.assertRaises(ValueError):
            import_identities(artifact, expected_target_key="example.com:443")

    def test_exported_artifact_file_round_trip(self) -> None:
        identity = capture_from_proxy(
            "example.com:443",
            "admin",
            method="GET",
            url="https://example.com:443/api/admin",
            headers={"Authorization": "Bearer file-token"},
            body="",
        )
        self.store.upsert_identity(identity)
        path = self.run_dir / "identities.json"
        export_identities_to_file(
            "example.com:443", self.store.list_identities("example.com:443"), path
        )
        text = path.read_text(encoding="utf-8")
        self.assertIn("file-token", text)  # creds preserved in the secret artifact
        reloaded = import_identities_from_file(path, expected_target_key="example.com:443")
        self.assertTrue(any(i.tokens.get("authorization") == "Bearer file-token" for i in reloaded))


if __name__ == "__main__":
    import unittest

    unittest.main()
