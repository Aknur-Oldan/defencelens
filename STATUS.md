# Status

What works, how it was verified, and what comes next. Nothing listed as working is unverified.

## Working and verified

| Capability | Verified by |
|---|---|
| Docker image upload (512 MiB cap, manifest validation, traversal/symlink rejection, never executed) | `backend/tests/test_api.py`, integration run |
| Trivy scan pipeline: pending → queued → running → completed/failed, 2 retries, timeout, secret values masked | unit tests + manual scan of `redis:7.4.2-alpine` |
| Dispatcher re-queues scans after Redis outage; failure is never shown as pass | `scripts/resilience.py` against the real stack |
| Deployment policy gate (max CRITICAL / max HIGH / secrets blocking) with pass/fail/error | `backend/tests/test_policy.py`, `scripts/policy_check.py` exit codes |
| Token-authenticated JSONL ingestion with accepted/duplicate/rejected counters and idempotency | `backend/tests/test_api.py`, concurrent replay in `scripts/integration.py` |
| Four deterministic detectors with explicit windows, late-event re-evaluation (±10 min) | `backend/tests/test_api.py` |
| 15-minute incident grouping: facts, ≤200 evidence links, impact, limitations, remediation, reopen on new evidence | unit + integration tests |
| Vector file tail → HTTP sink with disk buffer, acks, checkpoints | `scripts/integration.py` (file append observed through to API counters) |
| Attention index 0–100 with open formula, N/A without data | `backend/tests/test_api.py` dashboard checks |
| Scan comparison (new/resolved/remaining, scanner/DB version diffs) | API test with two completed scans |
| Operator-confirmed deployments requiring written evidence | `backend/tests/test_api.py` |
| Web UI journey: login → overview → incident → action → verify → sources → images | `scripts/browser-smoke.cjs` (Playwright) |
| Outcome verification after operator action, honest "insufficient data" | `scripts/verify-recovery.py` |

## How to re-verify

```bash
docker compose up -d --build
docker compose run --rm --no-deps -v "$PWD/backend:/app" api python -m pytest -q -p no:cacheprovider
python3 scripts/integration.py
node scripts/browser-smoke.cjs
```

## Not implemented (labeled in the UI where relevant)

- Multi-user accounts, RBAC, audit log export
- Automatic deployment discovery (deployments are operator statements)
- Log retention/cleanup policies
- Registry pulling (only `docker save` archives are accepted)
- Alert notifications (email/chat) — dashboard polling only

## Next step

Retention policies and a dead-letter store for rejected log lines, then notification channels.
