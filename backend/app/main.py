import hashlib
import hmac
import json
import tarfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, func, text
from sqlalchemy.exc import SQLAlchemyError
from redis import Redis
from rq import Worker
from app.config import settings
from app.db import session
from app.models import Service, Source, Event, Incident, Action, Scan, Deployment, now, uid
from app.analysis import normalize, analyze, utc

app = FastAPI(title="DefenceLens", version="0.1.0")

def auth(request: Request):
    if not hmac.compare_digest(request.headers.get("authorization", ""), "Bearer " + settings.api_token):
        raise HTTPException(401, "API token is required")

def row(obj):
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns}

def require(db, model, id):
    obj = db.get(model, id)
    if obj is None:
        raise HTTPException(404, "Record not found")
    return obj

@app.exception_handler(SQLAlchemyError)
async def database_error(request, exc):
    return JSONResponse(status_code=503, content={"detail": "Database is unavailable or the operation conflicts. Retry the request."})

@app.get("/api/health")
def health(db=Depends(session)):
    db.execute(text("SELECT 1"))
    return {"status": "ok"}

@app.get("/api/system", dependencies=[Depends(auth)])
def system(db=Depends(session)):
    db.execute(text("SELECT 1"))
    result = {"database": "ok", "redis": "unavailable", "worker": "unavailable"}
    try:
        r = Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
        r.ping()
        result["redis"] = "ok"
        result["worker"] = "ok" if Worker.all(connection=r) else "unavailable"
    except Exception:
        pass
    return result

class ServiceInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=2000)
    importance: int = Field(default=3, ge=1, le=5)
    environment: str = Field(default="production", min_length=1, max_length=60)
    dependencies: list[str] = Field(default_factory=list, max_length=50)

def validate_service(db, data, id=None):
    duplicate = db.scalar(select(Service).where(Service.name == data.name))
    if duplicate and duplicate.id != id:
        raise HTTPException(409, "Service name is already in use")
    services = {x.id: x.dependencies for x in db.scalars(select(Service))}
    if any(dep not in services or dep == id for dep in data.dependencies):
        raise HTTPException(422, "Dependency must reference another existing service")
    services[id or "new"] = data.dependencies
    def walk(key, path):
        if key in path:
            raise HTTPException(422, "Cyclic dependencies are not allowed")
        for dep in services.get(key, []):
            walk(dep, path | {key})
    for key in services:
        walk(key, set())

@app.get("/api/services", dependencies=[Depends(auth)])
def services(db=Depends(session)):
    return [row(x) for x in db.scalars(select(Service).order_by(Service.name))]

@app.post("/api/services", dependencies=[Depends(auth)])
def create_service(data: ServiceInput, db=Depends(session)):
    validate_service(db, data)
    obj = Service(**data.model_dump())
    db.add(obj)
    db.commit()
    return row(obj)

@app.put("/api/services/{id}", dependencies=[Depends(auth)])
def update_service(id: str, data: ServiceInput, db=Depends(session)):
    obj = require(db, Service, id)
    validate_service(db, data, id)
    for key, value in data.model_dump().items():
        setattr(obj, key, value)
    db.commit()
    return row(obj)

class SourceInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    service_id: str
    kind: Literal["http", "upload"] = "http"

@app.post("/api/sources", dependencies=[Depends(auth)])
def create_source(data: SourceInput, db=Depends(session)):
    require(db, Service, data.service_id)
    obj = Source(**data.model_dump())
    db.add(obj)
    db.commit()
    return row(obj)

@app.get("/api/sources", dependencies=[Depends(auth)])
def sources(db=Depends(session)):
    result = []
    for x in db.scalars(select(Source)):
        state = "never" if not x.last_received else "live" if datetime.fromisoformat(x.last_received) > datetime.now(timezone.utc) - timedelta(minutes=5) else "stale"
        latest = db.scalar(select(func.max(Event.timestamp)).where(Event.source_id == x.id))
        result.append(dict(row(x), state="error" if x.last_error else state, last_event=latest))
    return result

def ingest(db, source_id, lines):
    source = require(db, Source, source_id)
    db.execute(select(Service).where(Service.id == source.service_id).with_for_update()).scalar_one()
    db.refresh(source)
    accepted, duplicates, failures, timestamps = 0, 0, [], []
    if len(lines) > 2000:
        raise HTTPException(413, "No more than 2000 events per batch")
    for number, raw in enumerate(lines, 1):
        if isinstance(raw, str) and not raw.strip():
            continue
        try:
            data, key = normalize(raw)
        except (ValueError, TypeError, OverflowError) as exc:
            failures.append({"line": number, "error": str(exc)})
            continue
        old = db.scalar(select(Event.id).where(Event.source_id == source_id, Event.dedup_key == key))
        if old:
            duplicates += 1
            continue
        obj = Event(source_id=source_id, service_id=source.service_id, dedup_key=key, timestamp=data["timestamp"], data=data)
        db.add(obj)
        db.flush()
        timestamps.append(obj.timestamp)
        accepted += 1
    source.accepted += accepted
    source.duplicates += duplicates
    source.rejected += len(failures)
    source.last_received = now()
    source.last_error = f"Rejected lines: {len(failures)}" if failures else None
    if timestamps:
        analyze(db, source.service_id, min(timestamps), max(timestamps))
    db.commit()
    return {"accepted": accepted, "duplicates": duplicates, "rejected": len(failures), "errors": failures[:30]}

async def bounded_body(request, limit):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(413, "Batch size exceeded")
    return bytes(body)

@app.post("/api/ingest/{source_id}", dependencies=[Depends(auth)])
async def http_ingest(source_id: str, request: Request, db=Depends(session)):
    body = await bounded_body(request, settings.max_log_bytes)
    try:
        content = body.decode("utf-8")
        try:
            parsed = json.loads(content)
            lines = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            lines = content.splitlines()
    except UnicodeDecodeError:
        raise HTTPException(422, "UTF-8 is expected")
    return ingest(db, source_id, lines)

@app.post("/api/sources/{source_id}/upload", dependencies=[Depends(auth)])
async def upload_logs(source_id: str, file: UploadFile = File(...), db=Depends(session)):
    body = await file.read(settings.max_log_bytes + 1)
    if len(body) > settings.max_log_bytes:
        raise HTTPException(413, "Maximum log size: 5 MiB")
    try:
        lines = body.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        raise HTTPException(422, "UTF-8 is expected")
    return ingest(db, source_id, lines)

@app.get("/api/events", dependencies=[Depends(auth)])
def events(service_id: str | None = None, limit: int = 100, db=Depends(session)):
    query = select(Event)
    if service_id:
        query = query.where(Event.service_id == service_id)
    return [row(x) for x in db.scalars(query.order_by(Event.timestamp.desc()).limit(max(1, min(limit, 500))))]

def impact(db, service_id):
    services = list(db.scalars(select(Service)))
    affected = {service_id}
    while True:
        more = {s.id for s in services if set(s.dependencies) & affected}
        if more <= affected:
            break
        affected |= more
    return [{"id": s.id, "name": s.name, "description": s.description, "importance": s.importance,
             "relationship": "direct" if s.id == service_id else "dependent"} for s in services if s.id in affected]

@app.get("/api/incidents", dependencies=[Depends(auth)])
def incidents(db=Depends(session)):
    return [dict(row(x), impact=impact(db, x.service_id)) for x in db.scalars(select(Incident).order_by(Incident.updated_at.desc()).limit(200))]

@app.get("/api/incidents/{id}", dependencies=[Depends(auth)])
def incident(id: str, db=Depends(session)):
    obj = require(db, Incident, id)
    evidence = list(db.scalars(select(Event).where(Event.id.in_(obj.evidence_ids)).order_by(Event.timestamp)))
    deps = list(db.scalars(select(Deployment).where(Deployment.service_id == obj.service_id)))
    times = [e.timestamp for e in evidence] or [obj.created_at]
    deps = [row(d) for d in deps if d.started_at <= max(times) and (d.ended_at is None or d.ended_at >= min(times))]
    return dict(row(obj), evidence=[row(x) for x in evidence], impact=impact(db, obj.service_id),
                deployments=deps, actions=[row(x) for x in db.scalars(select(Action).where(Action.incident_id == id).order_by(Action.timestamp))])

class ActionInput(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"] | None = None
    note: str = Field(min_length=1, max_length=4000)

@app.post("/api/incidents/{id}/actions", dependencies=[Depends(auth)])
def action(id: str, data: ActionInput, db=Depends(session)):
    obj = require(db, Incident, id)
    old = obj.status
    if data.status:
        obj.status = data.status
    obj.updated_at = now()
    db.add(Action(incident_id=id, actor="local-operator", kind="status" if data.status else "note",
                  note=f"{old} → {obj.status}. {data.note}" if data.status else data.note))
    db.commit()
    return row(obj)

@app.post("/api/incidents/{id}/verify", dependencies=[Depends(auth)])
def verify(id: str, db=Depends(session)):
    obj = require(db, Incident, id)
    latest_action = db.scalar(select(Action).where(Action.incident_id == id, Action.kind != "verification").order_by(Action.timestamp.desc()))
    since = latest_action.timestamp if latest_action else obj.updated_at
    cutoff = max(since, (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat())
    fresh = list(db.scalars(select(Event).where(Event.service_id == obj.service_id, Event.timestamp > cutoff)))
    http = [x for x in fresh if "status" in x.data]
    errors = sum(x.data["status"] >= 500 for x in http)
    if obj.detector == "server_errors":
        result = "insufficient" if len(http) < 10 else "observed_improvement" if errors / len(http) < .3 else "still_detected"
        detail = f"After the last action, at most 5 minutes: {errors}/{len(http)} 5xx responses."
    else:
        result = "manual_review"
        detail = f"New events after the action: {len(fresh)}. Owner confirmation and session/access review require an operator."
    note = f"{result}: {detail} Absence of a repeated signal does not prove the threat is resolved."
    db.add(Action(incident_id=id, actor="rule-engine", kind="verification", note=note))
    db.commit()
    return {"result": result, "detail": note, "events": len(fresh)}

from app.images import router as image_router
from app.dashboard import router as dashboard_router
app.include_router(image_router)
app.include_router(dashboard_router)
