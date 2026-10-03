import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Integer, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.db import Base

def uid():
    return str(uuid.uuid4())

def now():
    return datetime.now(timezone.utc).isoformat()

class Service(Base):
    __tablename__ = "services"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String, unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    importance: Mapped[int] = mapped_column(Integer, default=3)
    environment: Mapped[str] = mapped_column(String, default="production")
    dependencies: Mapped[list] = mapped_column(JSON, default=list)

class Source(Base):
    __tablename__ = "sources"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"))
    kind: Mapped[str] = mapped_column(String, default="http")
    last_received: Mapped[str | None] = mapped_column(String, nullable=True)
    accepted: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

class Event(Base):
    __tablename__ = "events"
    __table_args__ = (UniqueConstraint("source_id", "dedup_key"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"), index=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    dedup_key: Mapped[str] = mapped_column(String)
    timestamp: Mapped[str] = mapped_column(String, index=True)
    received_at: Mapped[str] = mapped_column(String, default=now)
    data: Mapped[dict] = mapped_column(JSON)

class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    fingerprint: Mapped[str] = mapped_column(String, unique=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    detector: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    priority: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="open")
    created_at: Mapped[str] = mapped_column(String, default=now)
    updated_at: Mapped[str] = mapped_column(String, default=now)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    facts: Mapped[list] = mapped_column(JSON, default=list)
    hypotheses: Mapped[list] = mapped_column(JSON, default=list)
    limitations: Mapped[list] = mapped_column(JSON, default=list)
    recommendations: Mapped[list] = mapped_column(JSON, default=list)

class Action(Base):
    __tablename__ = "actions"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    timestamp: Mapped[str] = mapped_column(String, default=now)
    actor: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    note: Mapped[str] = mapped_column(Text)

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    filename: Mapped[str] = mapped_column(String)
    digest: Mapped[str] = mapped_column(String, index=True)
    status: Mapped[str] = mapped_column(String, default="pending")
    created_at: Mapped[str] = mapped_column(String, default=now)
    updated_at: Mapped[str] = mapped_column(String, default=now)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)

class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String, primary_key=True, default="default")
    max_critical: Mapped[int] = mapped_column(Integer, default=0)
    max_high: Mapped[int] = mapped_column(Integer, default=5)
    fail_on_secrets: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[str] = mapped_column(String, default=now)

class Deployment(Base):
    __tablename__ = "deployments"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    started_at: Mapped[str] = mapped_column(String)
    ended_at: Mapped[str | None] = mapped_column(String, nullable=True)
    confirmation: Mapped[str] = mapped_column(String)
    evidence: Mapped[str] = mapped_column(Text, default="")
