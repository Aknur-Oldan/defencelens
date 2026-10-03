# Limitations

DefenceLens is an MVP. These boundaries are deliberate and documented so that no capability is overstated.

## Scope and trust model

- Single trusted operator with one bearer token. No multi-user accounts, RBAC, or immutable external audit log.
- Ports bind to localhost by default. Exposing the system externally requires TLS, dedicated secrets, and network restrictions that are out of scope here.
- Action history is stored in the application database and can be edited by anyone with database access.

## Detection

- Four deterministic detectors with fixed windows. They cover brute force, success-after-failures, suspicious HTTP signatures, and 5xx surges — nothing else. Absence of alerts does not mean absence of threats.
- Signatures produce hypotheses, not proof. A matching request does not establish that an attack succeeded.
- The 5xx detector states explicitly when a baseline window is missing; growth is then unconfirmed.
- Window analysis runs in memory on ingest and targets small event streams. It does not replace a SIEM at large volumes.
- Late events re-evaluate a ±10 minute window; events later than that are stored but not re-analyzed.

## Scanning

- A CVE means a known vulnerable component, not proven exploitation or compromise.
- Results depend on the Trivy vulnerability database coverage and freshness; the DB timestamp is recorded on every scan.
- "Resolved" in a scan comparison means absent from the rescanned image — not that the fix is deployed. Deployment links require explicit operator confirmation with written evidence, and that confirmation is an operator statement, not automated verification.
- Only uncompressed `docker save` archives up to 512 MiB are accepted. Images are never executed; runtime behavior is not analyzed.
- Secret findings report rule, location, and severity only; matched values are never persisted or displayed.

## Data and operations

- Attention index is an explainable prioritization aid (open formula, capped at 100), not a probability of compromise. With no data it is N/A.
- Ingestion deduplicates on (source_id, SHA256(event_id)); identical events without `event_id` may collapse into one, and duplicates across different sources are not merged.
- No automatic retention or cleanup of events, scans, or uploaded archives — disk usage must be monitored.
- Rejected log lines are returned in the API response but there is no dead-letter store.
- Verification of incident outcomes analyzes only newly received logs; absence of a repeated signal does not prove the threat is resolved.
- Synthetic demo data is always tagged `"synthetic": true` and loaded only by an explicit action; it is intentionally mixed into the same pipeline to demonstrate it, and can be identified by its tag.

## Production readiness

Production use would additionally require load testing, backups, retention policies, hardened authentication, and monitoring of the monitoring system itself.
