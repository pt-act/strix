"""Minimal seeded target for Phase-5 business-logic integration testing.

Set ``VULN_MODE=1`` for the vulnerable configuration (double-spend + price-mismatch).
Set ``VULN_MODE=0`` for the patched configuration (locking + server-side total check).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


app = FastAPI()
VULN_MODE = os.getenv("VULN_MODE", "1") == "1"


class Checkout(BaseModel):
    price: int
    quantity: int
    total: int


@dataclass
class _State:
    redeemed: bool = False
    redeem_count: int = 0
    balance: int = 100


state = _State()


@app.post("/reset")
def reset() -> dict[str, str]:
    """Reset the target to a known baseline."""
    state.redeemed = False
    state.redeem_count = 0
    state.balance = 100
    return {"status": "reset"}


@app.get("/state")
def state_endpoint() -> dict[str, int]:
    """Return the current observable state."""
    return {"redeem_count": state.redeem_count, "balance": state.balance}


@app.post("/redeem")
def redeem() -> dict[str, object]:
    """Redeem a single-use coupon."""
    if VULN_MODE:
        # Vulnerable: no locking; concurrent copies can all commit.
        state.redeem_count += 1
        state.balance -= 10
        return {"status": "redeemed", "balance": state.balance}

    # Patched: single-use gate.
    if state.redeemed:
        raise HTTPException(status_code=409, detail="already_used")
    state.redeemed = True
    state.redeem_count = 1
    state.balance -= 10
    return {"status": "redeemed", "balance": state.balance}


@app.post("/checkout")
def checkout(data: Checkout) -> dict[str, object]:
    """Process a checkout request."""
    expected = data.price * data.quantity

    if VULN_MODE:
        # Vulnerable: computes the charged total from the tampered price but
        # accepts the request anyway, so the client sees a wrong total.
        return {"status": "paid", "total": expected}

    # Patched: recomputes the total server-side and rejects mismatches.
    if data.total != expected:
        raise HTTPException(
            status_code=400,
            detail={"status": "rejected", "total": expected},
        )
    return {"status": "paid", "total": expected}
