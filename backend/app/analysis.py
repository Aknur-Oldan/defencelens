import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote
from sqlalchemy import select
from app.models import Event, Incident, Service, now

NGINX = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^]]+)\] "(?P<method>\S+) (?P<path>.*?) HTTP/[^"]+" (?P<status>\d{3}) ')
SUSPICIOUS = re.compile(r"\.\./|/\.env(?:$|\?)|/\.git|union\s+select|<script|/etc/passwd|/wp-admin", re.I)

def utc(value):
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return dt.astimezone(timezone.utc).isoformat()

def normalize(raw):
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            m = NGINX.match(raw)
            if not m:
                raise ValueError("expected JSON object or Nginx combined/common access log")
            d = m.groupdict()
            raw = dict(timestamp=datetime.strptime(d["time"], "%d/%b/%Y:%H:%M:%S %z").isoformat(),
                       ip=d["ip"], method=d["method"], path=d["path"], status=int(d["status"]))
    if not isinstance(raw, dict):
        raise ValueError("event must be an object")
    if "message" in raw and "status" not in raw and "event" not in raw:
        return normalize(raw["message"])
    if not raw.get("timestamp"):
        raise ValueError("timestamp is required; event time must not be invented")
    ts = utc(raw["timestamp"])
    if datetime.fromisoformat(ts) > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ValueError("timestamp is more than 5 minutes in the future")
    data = {k: raw[k] for k in ("event_id", "ip", "user", "method", "path", "status", "event", "message", "synthetic") if k in raw}
    for k in ("event_id", "ip", "user", "method", "path", "event", "message"):
        if k in data:
            if not isinstance(data[k], str) or len(data[k]) > 8192:
                raise ValueError(f"{k}: expected string up to 8192 characters")
    if "status" in data:
        data["status"] = int(data["status"])
        if not 100 <= data["status"] <= 599:
            raise ValueError("invalid HTTP status")
    data["timestamp"] = ts
    key = str(data.get("event_id")) if data.get("event_id") else json.dumps(data, sort_keys=True, ensure_ascii=False)
    return data, hashlib.sha256(key.encode()).hexdigest()

def analyze(db, service_id, start, end):
    service = db.get(Service, service_id)
    lo = (datetime.fromisoformat(start) - timedelta(minutes=10)).isoformat()
    hi = (datetime.fromisoformat(end) + timedelta(minutes=10)).isoformat()
    events = list(db.scalars(select(Event).where(Event.service_id == service_id, Event.timestamp >= lo, Event.timestamp <= hi).order_by(Event.timestamp, Event.id)))
    for e in events:
        t = datetime.fromisoformat(e.timestamp)
        window = [x for x in events if t - timedelta(minutes=5) <= datetime.fromisoformat(x.timestamp) <= t]
        d = e.data
        principal = (d.get("ip"), d.get("user"))
        failures = [x for x in window if x.data.get("event") == "login_failed" and (x.data.get("ip"), x.data.get("user")) == principal]
        if d.get("event") == "login_failed" and len(failures) >= 5 and any(principal):
            record(db, service, "failed_logins", e, failures, principal, "Burst of failed logins", "P2",
                   [f"{len(failures)} failed login attempts in 5 minutes; IP: {d.get('ip', 'n/a')}, account: {d.get('user', 'n/a')}"],
                   ["Password guessing is possible; user error is also possible."],
                   ["Check the request source and account owner.", "If password guessing is confirmed, rate-limit logins and enable MFA."])
        if d.get("event") == "login_success" and len(failures) >= 5 and any(principal):
            record(db, service, "success_after_failures", e, failures + [e], principal, "Login after repeated failures", "P1",
                   [f"Successful login after {len(failures)} failures in 5 minutes for the same IP and user."],
                   ["The account may be compromised; a successful login alone does not prove it."],
                   ["Contact the account owner and review the active session.", "If the login is not recognized, revoke the session and rotate secrets manually."])
        if SUSPICIOUS.search(unquote(unquote(d.get("path", "")))):
            record(db, service, "suspicious_http", e, [e], d.get("ip"), "Suspicious HTTP request", "P2",
                   [f"Request matches signature: {d.get('method', 'HTTP')} {d.get('path')}"],
                   ["Automated scanning is possible; attack execution is not established."],
                   ["Review the response code, application logs, and access to the requested resource.", "Block access to service files and review gateway rules."])
        current = [x for x in window if "status" in x.data]
        baseline = [x for x in events if t - timedelta(minutes=10) <= datetime.fromisoformat(x.timestamp) < t - timedelta(minutes=5) and "status" in x.data]
        errors = [x for x in current if x.data["status"] >= 500]
        ratio = len(errors) / len(current) if current else 0
        old = sum(x.data["status"] >= 500 for x in baseline) / len(baseline) if baseline else None
        if len(current) >= 10 and len(errors) >= 5 and ratio >= .3 and (old is None or ratio >= old + .2):
            facts = [f"5xx: {len(errors)}/{len(current)} ({ratio:.0%}) over 5 minutes."]
            facts += [f"Previous 5 minutes: {old:.0%} errors."] if old is not None else ["No baseline period: a high level was detected, but growth is not proven."]
            record(db, service, "server_errors", e, current, "service", "Rising or high API error rate", "P1" if service.importance >= 4 else "P2", facts,
                   ["An application or dependency failure is possible; temporal correlation with other events does not prove causation."],
                   ["Check API and database availability, starting with a health check.", "Correlate errors with deployments; consider rollback only after verification.", "After taking action, review new logs and submit a test request."])

def record(db, service, detector, event, evidence, principal, title, priority, facts, hypotheses, recommendations):
    recent = db.scalar(select(Incident).where(Incident.service_id == service.id, Incident.detector == detector,
        Incident.fingerprint.like(hashlib.sha256(json.dumps(principal, sort_keys=True).encode()).hexdigest() + ":%"),
        Incident.created_at >= (datetime.fromisoformat(event.timestamp) - timedelta(minutes=15)).isoformat(),
        Incident.created_at <= event.timestamp).order_by(Incident.created_at.desc()))
    ids = list(dict.fromkeys([x.id for x in evidence]))
    limitations = ["Rules analyze only received logs; absence of events does not mean absence of threats.", "CVEs and matching timestamps are not evidence of compromise or root cause."]
    if recent:
        added = set(ids) - set(recent.evidence_ids)
        recent.evidence_ids = list(dict.fromkeys(recent.evidence_ids + ids))[-200:]
        recent.facts = facts
        recent.updated_at = now()
        if added and recent.status == "resolved":
            recent.status = "open"
        return
    fp = hashlib.sha256(json.dumps(principal, sort_keys=True).encode()).hexdigest() + ":" + detector + ":" + service.id + ":" + event.id
    db.add(Incident(fingerprint=fp, service_id=service.id, detector=detector, title=title, priority=priority,
        created_at=event.timestamp, evidence_ids=ids[-200:], facts=facts, hypotheses=hypotheses,
        limitations=limitations + ["The card stores up to 200 evidence items; the full stream is available in the event log."], recommendations=recommendations))
    db.flush()
