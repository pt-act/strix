"""B-V2P SSRF pair — Flowise HTTP-node (CVE-2026-31829). Thin FastAPI wrapper over ``core``.

``VULN_MODE=1`` (vulnerable): ``POST /api/v1/node/http`` fetches **any** user-supplied URL (SSRF).
``VULN_MODE=0`` (patched, the <=3.0.12 -> 3.0.13 fix): blocks internal/metadata targets via the
P0 net classifier before fetching. The P3 OOB oracle's callback fires on vuln, not on patch.
"""

from __future__ import annotations

from core import perform_fetch, screen_fetch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


app = FastAPI()


class FetchBody(BaseModel):
    url: str


@app.post("/api/v1/node/http")
def http_node(body: FetchBody) -> dict[str, object]:
    allowed, reason = screen_fetch(body.url)
    if not allowed:
        raise HTTPException(status_code=400, detail={"status": "blocked", "reason": reason})
    return {
        "status": "fetched",
        "url": body.url,
        "reason": reason,
        "upstream_status": perform_fetch(body.url),
    }
