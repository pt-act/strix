"""B-V2P IDOR pair — open-webui memories (CVE-2024-7041). Thin FastAPI wrapper over ``core``.

``VULN_MODE=1`` (vulnerable): ``POST /api/v1/memories/{id}/update`` updates **any** memory.
``VULN_MODE=0`` (patched): adds the one-line ownership check (see ``core.update_memory``).

The disposer is the P2 differential engine: the attacker's cross-user request is 2xx on vuln and
403 on patch, so the harness verdict flips across the pair while the raw proposal does not.
"""

from __future__ import annotations

from core import MemoryAccessError, read_memory, reset_state, update_memory
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel


app = FastAPI()


class UpdateBody(BaseModel):
    content: str


@app.post("/reset")
def reset() -> dict[str, str]:
    reset_state()
    return {"status": "reset"}


@app.get("/api/v1/memories/{memory_id}")
def read_route(memory_id: str) -> dict[str, object]:
    try:
        return read_memory(memory_id)
    except MemoryAccessError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@app.post("/api/v1/memories/{memory_id}/update")
def update_route(
    memory_id: str, body: UpdateBody, x_user_id: str = Header(default="anonymous")
) -> dict[str, object]:
    try:
        return update_memory(memory_id, x_user_id, body.content)
    except MemoryAccessError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
