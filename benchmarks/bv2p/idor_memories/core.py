"""Pure IDOR logic for the open-webui memories B-V2P pair (CVE-2024-7041).

No web-framework import, so the ground-truth behaviour is unit-testable without fastapi.
``app.py`` is the thin FastAPI wrapper around this. ``VULN_MODE=0`` adds the one-line ownership
check — the whole synthesized minimal diff.
"""

from __future__ import annotations

import os


class MemoryAccessError(Exception):
    """Raised on a denied/missing access; ``status_code`` mirrors the HTTP the wrapper returns."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class Memory:
    def __init__(self, user_id: str, content: str) -> None:
        self.user_id = user_id
        self.content = content


_MEMORIES: dict[str, Memory] = {}


def is_vuln() -> bool:
    return os.getenv("VULN_MODE", "1") == "1"


def reset_state() -> None:
    _MEMORIES.clear()
    _MEMORIES["mem-1"] = Memory("alice", "alice private note")
    _MEMORIES["mem-2"] = Memory("bob", "bob private note")


reset_state()


def read_memory(memory_id: str) -> dict[str, object]:
    memory = _MEMORIES.get(memory_id)
    if memory is None:
        raise MemoryAccessError(404, "not_found")
    return {"id": memory_id, "user_id": memory.user_id, "content": memory.content}


def update_memory(memory_id: str, caller: str, content: str) -> dict[str, object]:
    """Update a memory. Raises ``MemoryAccessError`` (404 unknown / 403 patched non-owner)."""
    memory = _MEMORIES.get(memory_id)
    if memory is None:
        raise MemoryAccessError(404, "not_found")
    if not is_vuln() and memory.user_id != caller:
        # Patched: the one-line ownership check (the synthesized minimal diff).
        raise MemoryAccessError(403, "forbidden")
    memory.content = content
    return {"id": memory_id, "user_id": memory.user_id, "content": memory.content}
