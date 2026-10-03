from collections import defaultdict
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from app.db import session
from app.models import Service, Source, Event, Incident, Scan, Deployment, now
from app.main import auth, row, ingest

router = APIRouter(prefix="/api", dependencies=[Depends(auth)])

@router.get("/dashboard")
def dashboard(db=Depends(session)):
    active = list(db.scalars(select(Incident).where(Incident.status.in_(["open", "investigating"]))))
    services = {s.id: s for s in db.scalars(select(Service))}
    priority = {"P1": 25, "P2": 12, "P3": 5}
    contributions = [{"label": i.title, "points": round(priority[i.priority] * services[i.service_id].importance / 5), "type": "incident"} for i in active]
    confirmed = set(db.scalars(select(Deployment.scan_id).where(Deployment.confirmation == "operator_confirmed", Deployment.started_at <= now(),
        (Deployment.ended_at.is_(None)) | (Deployment.ended_at > now()))))
    scans = list(db.scalars(select(Scan)))
    for scan in scans:
        if scan.id in confirmed and scan.result:
            severity = scan.result["summary"]["severity"]
            points = min(15, severity.get("CRITICAL", 0) * 5 + severity.get("HIGH", 0) * 2)
            if points:
                contributions.append({"label": f"Vulnerabilities in confirmed deployment: {scan.filename}", "points": points, "type": "exposure"})
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    events = list(db.scalars(select(Event).where(Event.timestamp >= cutoff.isoformat())))
    buckets = {}
    for minute in range(60):
        stamp = (cutoff + timedelta(minutes=minute + 1)).replace(second=0, microsecond=0).isoformat()
        buckets[stamp] = {"time": stamp, "events": 0, "errors": 0}
    for e in events:
        stamp = datetime.fromisoformat(e.timestamp).replace(second=0, microsecond=0).isoformat()
        if stamp in buckets:
            buckets[stamp]["events"] += 1
            buckets[stamp]["errors"] += int(e.data.get("status", 0) >= 500)
    return {"risk": min(100, sum(c["points"] for c in contributions)), "contributions": contributions,
            "risk_explanation": "Sum: P1=25, P2=12, P3=5 × service importance/5; active confirmed image: Critical×5 + High×2, up to 15 per image. Overall cap is 100. This is an attention priority, not a probability of compromise.",
            "limitations": "Unconfirmed image links do not increase the score. No logs means no coverage assessment, not a security guarantee. CVEs do not prove exploitation.",
            "events_total": db.scalar(select(func.count()).select_from(Event)), "events_hour": len(events),
            "errors_hour": sum(e.data.get("status", 0) >= 500 for e in events), "active_incidents": len(active),
            "services": len(services), "scans_completed": sum(s.status == "completed" for s in scans),
            "series": list(buckets.values()), "synthetic_events": sum(bool(e.data.get("synthetic")) for e in events)}

@router.post("/demo")
def demo(db=Depends(session)):
    existing = db.get(Source, "demo-api")
    if existing:
        return {"detail": "Demo is already loaded. Re-running it does not create duplicates.", "source_id": existing.id}
    db.add(Service(id="demo-db", name="volunteer-db", description="Request and contact database", importance=5, dependencies=[]))
    db.flush()
    db.add(Service(id="demo-api-service", name="volunteer-api", description="Receives requests for help. Outage prevents people from submitting requests.", importance=5, dependencies=["demo-db"]))
    db.flush()
    db.add(Service(id="demo-gateway", name="volunteer-gateway", description="Volunteer center entry point", importance=4, dependencies=["demo-api-service"]))
    db.flush()
    db.add(Source(id="demo-api", name="Demo · synthetic logs", service_id="demo-api-service", kind="upload"))
    db.add(Source(id="vector-demo", name="Vector · file tail", service_id="demo-api-service", kind="http"))
    db.flush()
    base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=12)
    logs = []
    for n in range(25):
        logs.append({"event_id": f"demo-baseline-{n}", "timestamp": (base + timedelta(seconds=n*6)).isoformat(), "status": 200, "method": "POST", "path": "/requests", "synthetic": True})
    for n in range(6):
        logs.append({"event_id": f"demo-auth-{n}", "timestamp": (base + timedelta(minutes=7, seconds=n*8)).isoformat(), "event": "login_failed", "ip": "203.0.113.24", "user": "coordinator", "synthetic": True})
    logs.append({"event_id": "demo-success", "timestamp": (base + timedelta(minutes=8)).isoformat(), "event": "login_success", "ip": "203.0.113.24", "user": "coordinator", "synthetic": True})
    logs.append({"event_id": "demo-probe", "timestamp": (base + timedelta(minutes=8, seconds=5)).isoformat(), "status": 403, "path": "/.env", "ip": "203.0.113.24", "synthetic": True})
    for n in range(20):
        logs.append({"event_id": f"demo-errors-{n}", "timestamp": (base + timedelta(minutes=9, seconds=n*6)).isoformat(), "status": 503 if n < 14 else 200, "method": "POST", "path": "/requests", "synthetic": True})
    return dict(ingest(db, "demo-api", logs), source_id="demo-api", detail="Synthetic data loaded. Image scans are not faked.")
