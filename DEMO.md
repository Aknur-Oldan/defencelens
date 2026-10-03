# Demo script (3–5 minutes)

Audience: hackathon jury. Goal: show the full journey — image scan → policy gate → log ingestion → incident → operator action → verification. All demo data is synthetic and labeled `"synthetic": true`.

## Preparation (before the demo)

```bash
cp .env.example .env
docker compose up -d --build
docker save redis:7.4.2-alpine -o /tmp/redis.tar
```

Open http://localhost:18080 and sign in with the token from `.env` (`local-development-token` by default). The database starts empty — that is intentional.

## Minute 0–1 · Problem and empty state

- "Small organizations run critical services with no security staff. DefenceLens gives them scanning, detection, and plain-language incidents in one `docker compose up`."
- Show the empty Overview: the attention index is **N/A** because there is no data. We never invent numbers.
- Click **Load demo** — an explicit action; synthetic events are tagged and visible as such.

## Minute 1–2 · Incidents with evidence, not alerts

- Overview now shows the attention index with a link to its open formula (P1=25, P2=12, P5=5 × importance/5, capped at 100) and a 60-minute event timeline.
- Open the **"Rising or high API error rate"** incident: facts (counts and windows), up to 200 evidence events, impact on dependent services, explicit limitations ("signatures are hypotheses, not proof"), and practical remediation steps.
- Save an **Investigating** action with a note, then click **Verify outcome** — the system re-analyzes events after your action and honestly reports "insufficient data" when there is none. Closing an incident alone never improves the index.

## Minute 2–3 · Real image scanning, never executed

- Images page: upload `/tmp/redis.tar`. The archive manifest is validated; the image is **never executed**; the worker has no Docker socket, runs non-root with all capabilities dropped.
- While Trivy runs, show the scan lifecycle: pending → queued → running → completed. A failed scan is a visible error, never a passed check.
- Open the result: real CVEs with severity, SBOM components, potential secrets with values masked.

## Minute 3–4 · Policy gate for CI

```bash
python3 scripts/policy_check.py --token local-development-token --scan-id <SCAN_ID>
```

- Exit code 0 = pass, 1 = fail, 2 = error — drop-in required CI step.
- Show GET `/api/scans/{a}/compare/{b}` (or the UI compare view) for two scans: new / resolved / remaining findings, with scanner and vulnerability-DB version differences called out.

## Minute 4–5 · Live pipeline and honest limits

- Append a JSONL line to `demo/logs/live.jsonl` — Vector (disk buffer, retries, checkpoints) delivers it; the Sources page updates within 5 s with accepted/duplicate/rejected counters and source health.
- Close with LIMITATIONS.md: single operator, no RBAC, rules are deterministic and explainable, a CVE is not proof of compromise. "We tell you exactly what we know, what we assume, and what we cannot know."
