# DefenceLens

**Security monitoring that small organizations can actually run.**

A working MVP for a small volunteer center / NGO: logs → detectors → incidents → evidence → impact → recommendations → outcome verification. One `docker compose up`, one operator, plain-language explanations — no SIEM budget, no security team required.

## The problem

Small organizations (volunteer centers, NGOs, local services) run critical coordination infrastructure but have **no security staff and no budget** for enterprise tooling. When their request portal starts failing or an account is brute-forced, nobody notices until the service is down — and even then, nobody knows what to do next. Existing solutions assume experts, cloud subscriptions, and endless tuning.

## Why existing solutions fall short — 20 gaps DefenceLens closes

| # | Weakness of existing tools (SIEM/ELK/Wazuh/Splunk/cloud suites) | How DefenceLens addresses it |
|---|---|---|
| 1 | Require dedicated security analysts to interpret alerts | Incidents written as plain-language facts, limitations, and next steps |
| 2 | Expensive licensing / per-GB ingest pricing | Fully open-source stack, runs on one small host |
| 3 | Complex multi-day installation and tuning | `docker compose up -d --build` — minutes to a working system |
| 4 | Alert floods with no prioritization | Nearby detections merged into 15-minute episodes with P1/P2/P3 severity |
| 5 | Alerts without evidence — operator must dig through raw logs | Every incident stores up to 200 linked evidence events and a timeline |
| 6 | No connection between an alert and its business impact | Impact view: which service is affected and what it blocks (e.g. request intake) |
| 7 | Overconfident verdicts ("you are compromised") | Explicit limitations on every incident: signatures are hypotheses, not proof |
| 8 | No follow-through: alert closed, problem unverified | "Verify outcome" re-analyzes events after the operator's action and reports "insufficient data" honestly |
| 9 | Opaque risk scores | Attention index with an open, documented formula (P1=25, P2=12, P3=5 × importance; capped at 100) |
| 10 | Silent data loss on malformed logs | Accepted / duplicate / rejected line counters shown separately; invalid lines returned in `errors` |
| 11 | Duplicate events skew statistics on retries | Idempotent ingest: unique `(source_id, SHA256(event_id))` |
| 12 | Pipelines lose data when a component restarts | Vector disk buffers + acknowledgements; durable pending scans in PostgreSQL; dispatcher re-queues after Redis recovery |
| 13 | Vulnerability scanning is a separate product | Built-in Trivy image scanning: real CVEs, components, potential secrets (secret values never stored) |
| 14 | Scanners execute or deeply trust untrusted images | Image is never run; archive manifest validated before unpack; worker is non-root, no capabilities, no Docker socket |
| 15 | No link between "CVE found" and "fix deployed" | Deployment confirmation flow requiring grounds (CI digest or deployment record), clearly marked as an operator statement |
| 16 | Late or out-of-order logs break detection windows | Late events trigger re-evaluation of a ±10 minute window |
| 17 | Error-rate alerts fire on static thresholds alone | 5xx detector checks volume, share ≥30% and ≥20 pp growth vs the preceding window; states when baseline is missing |
| 18 | Dashboards hide how numbers are computed | Every chart and index links to an explanation of its calculation |
| 19 | Demo/synthetic data mixed invisibly with real data | Synthetic data is loaded only explicitly and tagged `"synthetic": true`; the DB starts empty |
| 20 | Degraded mode is undefined (what if Redis/Trivy/network is down?) | UI shows waiting/error/retry states; Trivy gets automatic retries plus manual retry; system keeps ingesting while scans wait |

## Documentation

- [DEMO.md](DEMO.md) — 3–5 minute jury demo script
- [LIMITATIONS.md](LIMITATIONS.md) — explicit boundaries of the MVP
- [STATUS.md](STATUS.md) — what works, how it was verified, next step
- [DefenceLens-presentation.pdf](DefenceLens-presentation.pdf) — slide deck

## Quick start

Requires Docker Engine and Docker Compose. No Node.js, Python, or Trivy needed on the host.

```bash
cp .env.example .env
docker compose up -d --build
```

- Web UI: http://localhost:18080
- API / OpenAPI: http://localhost:18000/docs
- Local demo token: `local-development-token` (change `API_TOKEN` in `.env`)
- The first scan downloads the Trivy database from the internet; the UI shows waiting, error, and retry states.

Ports are bound to localhost. Before exposing externally, configure TLS, dedicated secrets, and access restrictions. The MVP uses a single operator bearer token, not a multi-user access model.

## 5-minute demo

1. Sign in with `API_TOKEN`. Click **Load demo** — an explicit action that creates **synthetic** data; the DB is never auto-populated.
2. The overview shows four detectors, a chart, and the attention index. Open the calculation explanation.
3. Open the API-errors incident. Read the facts, limitations, timeline, and impact on the gateway: API unavailability blocks request submission.
4. In the incident card, save an **In progress** action with a note. **Verify outcome** analyzes events after the action (up to 5 minutes); with no new HTTP responses it reports "insufficient data".
5. In **Sources**, upload JSONL or an Nginx common/combined access.log. Accepted, duplicate, and rejected line counts are shown separately.
6. For the streaming scenario, append JSONL to `demo/logs/live.jsonl`. After loading the demo, Vector is already wired to `vector-demo`; updates appear without a reload.
7. `docker save redis:7.4.2-alpine -o /tmp/redis.tar`; upload the archive on the **Images** page. The image is never executed. Trivy shows real CVEs, components, and potential secrets (secret values are not stored).
8. Pick a service and a deployment period. Operator confirmation requires grounds: a digest from CI/deployment or a link to a deployment record. This is an operator statement, not automated runtime verification.

To use your own Vector, create a service and a source, set `VECTOR_SOURCE_ID` in `.env`, and run `docker compose up -d vector`. Example config: `vector/vector.yaml`. The collection directory can be changed in the Compose volume.

## Log format

JSONL, a JSON array, or a single object over HTTP. `timestamp` is required and must include a timezone.

```json
{"event_id":"stable-id-123","timestamp":"2026-10-03T16:00:00Z","event":"login_failed","user":"coordinator","ip":"203.0.113.24"}
{"event_id":"stable-id-124","timestamp":"2026-10-03T16:00:01Z","status":503,"method":"POST","path":"/requests"}
```

Replace the example timestamps with the current time. Authentication event types: `login_failed`, `login_success`. An HTTP 401 alone is not classified as an authentication failure. Tag demo data with `"synthetic": true`.

```bash
curl -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @events.jsonl \
  http://localhost:18000/api/ingest/SOURCE_ID
```

Idempotency: unique `(source_id, SHA256(event_id))`; without `event_id`, the normalized event is hashed. Keep the same `event_id` on retries. Identical events without IDs may collapse into one. Delivery across different sources is not deduplicated automatically.

The HTTP acknowledgement is sent after the PostgreSQL transaction commits. Concurrent retried batches are serialized by a per-service lock. Invalid lines are returned in `errors` and counted as rejected. Valid lines in a mixed batch are accepted; Vector does not auto-fix invalid lines. Rejected input stays in the source file; the MVP has no dedicated dead-letter storage. Batch limit: 2000 events / 5 MiB.

## Detectors

- 5 failures from the same IP/user within 5 minutes.
- A successful login by the same pair after ≥5 failures within 5 minutes.
- HTTP signatures: traversal, `.env`/`.git`, SQL `union select`, `script`, `wp-admin`.
- ≥10 HTTP events in 5 minutes, ≥5 responses with 5xx, share ≥30%, growth ≥20 percentage points vs the preceding 5 minutes. Without a baseline, a high level is recorded and growth is explicitly unconfirmed.

Analysis runs synchronously on ingest, without an LLM or Redis. Late events re-evaluate a ±10 minute window. Nearby detections merge into a 15-minute episode; up to 200 evidence links are kept. New facts may reopen a resolved episode.

Signatures produce hypotheses, not confirmation of a breach. Absence of logs does not mean absence of threats. No actions are executed on servers.

## Architecture & resilience

- **Backend:** FastAPI / Pydantic / SQLAlchemy / Alembic, PostgreSQL 16.
- **Frontend:** React / TypeScript / Vite, TanStack Query polling (5 s), Recharts, Tailwind, shared UI components.
- **Scanning:** the RQ worker runs only the Trivy binary with fixed arguments; the user's image is never executed and the Docker socket is not mounted.
- **Durability:** PostgreSQL stores durable pending scan records. The dispatcher reconciles them with RQ every 5 seconds; after Redis recovers, jobs are re-queued.
- **Retries:** Trivy gets two automatic retries; a final failure allows a manual retry. Redis AOF and PostgreSQL use persistent volumes.
- **Pipeline:** Vector uses disk buffers, acknowledgements, HTTP delivery retries, and file checkpoints.
- **Archives:** streaming upload up to 512 MiB; manifest and external path/link validation before unpacking. Worker: non-root, `no-new-privileges`, no capabilities, 2 CPU / 2 GiB.
- Trivy results never store secret Match/Code sections. CVE links in the UI allow HTTPS only.
- **Attention index:** P1=25, P2=12, P3=5 × importance/5; up to 15 for the current confirmed image (Critical×5 + High×2); the total is capped at 100. It is not a probability of compromise.

## Testing

```bash
# Isolated API and rule tests (SQLite in tests only)
docker compose run --rm --no-deps -v "$PWD/backend:/app" api python -m pytest -q -p no:cacheprovider

# Real DB, concurrent delivery, Vector; adds events tagged synthetic
python3 scripts/integration.py

# Browser: requires Playwright + Chrome installed
node scripts/browser-smoke.cjs
```

For the browser smoke test, the `playwright` module must be resolvable by Node (e.g. via `NODE_PATH`). `BASE_URL`, `WEB_URL`, and `API_TOKEN` are configured via environment variables. Screenshots are saved to `test-results`.

```bash
docker compose ps
docker compose logs --tail 100 api worker dispatcher vector
docker compose stop
# Restarting preserves data
docker compose up -d
```

## MVP boundaries (honest limitations)

Single trusted operator; no RBAC or immutable external audit. Action history is stored in the DB. No automatic deployment discovery, exploit verification, or guaranteed coverage of all attacks. No automatic cleanup of old logs/images: monitor disk usage. Window analysis runs in memory and targets a small event stream — it does not replace a SIEM at large volumes. Production use requires load testing, retention policies, backups, and hardened authentication.

A confirmed deployment is an operator statement with grounds. Temporal proximity of events does not prove causality. A CVE does not prove exploitation. Image scanning does not replace runtime logs.

## AI & resource disclosure

Built during HackYeah. AI coding assistants (GitHub Copilot) were used for development, translation, and documentation. External open-source components: [Trivy](https://trivy.dev/docs/dev/references/configuration/cli/trivy_image/) (image scanning), [Vector](https://vector.dev/docs/reference/configuration/sinks/http/) (log pipeline), [RQ](https://python-rq.org/docs/) (job queue), [Vite](https://vite.dev/guide/), FastAPI, PostgreSQL, Redis, React, Tailwind, Recharts — used under their respective open-source licenses. The team understands and can explain every component of the solution.
