# Business-Logic Fixture

Seeded target for Phase-5 integration validation (VALIDATION_PROTOCOL §E).

Two business-logic bugs in one app:
- **double-spend** on `POST /redeem` when `VULN_MODE=1` (no locking).
- **price-mismatch** on `POST /checkout` when `VULN_MODE=1` (trusts client-supplied total).

Patched mode (`VULN_MODE=0`) fixes both:
- `/redeem` rejects a second redemption with HTTP 409.
- `/checkout` recomputes `price * quantity` server-side and rejects mismatches with HTTP 400.

## Run

```bash
docker build -t strix-business-logic-fixture .
docker run -p 8080:8080 -e VULN_MODE=1 strix-business-logic-fixture
```

## Endpoints

- `POST /reset` — reset state to baseline.
- `GET /state` — read `redeem_count` and `balance`.
- `POST /redeem` — redeem a single-use coupon.
- `POST /checkout` — checkout with `{price, quantity, total}`.
