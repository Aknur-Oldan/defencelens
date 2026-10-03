import hashlib
import json
import tarfile
from pathlib import Path, PurePosixPath
from datetime import datetime
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from app.main import auth, row, require
from app.db import session
from app.config import settings
from app.models import Scan, Deployment, Service, Policy, uid, now
from app.analysis import utc

router = APIRouter(prefix="/api", dependencies=[Depends(auth)])

def validate_archive(path):
    with tarfile.open(path, mode="r:") as archive:
        manifest = None
        names = set()
        count = 0
        for member in archive:
            count += 1
            p = PurePosixPath(member.name)
            if count > 100000 or p.is_absolute() or ".." in p.parts or member.issym() or member.islnk():
                raise ValueError("Unsafe archive structure")
            names.add(member.name)
            if member.name == "manifest.json":
                if member.size > 1024 * 1024:
                    raise ValueError("Manifest is too large")
                manifest = json.load(archive.extractfile(member))
        if not isinstance(manifest, list) or not manifest:
            raise ValueError("An uncompressed docker save archive with manifest.json is required")
        for item in manifest:
            if not isinstance(item, dict) or item.get("Config") not in names or not isinstance(item.get("Layers"), list) or any(layer not in names for layer in item["Layers"]):
                raise ValueError("Incomplete docker save manifest")

@router.post("/scans")
async def upload_image(file: UploadFile = File(...), db=Depends(session)):
    id = uid()
    folder = Path(settings.data_dir) / "images"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{id}.tar"
    size = 0
    digest = hashlib.sha256()
    try:
        with path.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > settings.max_image_bytes:
                    raise HTTPException(413, "Maximum image size: 512 MiB")
                out.write(chunk)
                digest.update(chunk)
        try:
            validate_archive(path)
        except (tarfile.TarError, ValueError, KeyError, TypeError, OSError):
            raise HTTPException(422, "Invalid or unsafe docker save archive")
        obj = Scan(id=id, filename=(file.filename or "image.tar")[:200], digest=digest.hexdigest())
        db.add(obj)
        db.commit()
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return row(obj)

@router.get("/scans")
def scans(db=Depends(session)):
    result = []
    for s in db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(100)):
        value = row(s)
        report = value.pop("result") or {}
        value["summary"] = report.get("summary")
        result.append(value)
    return result

@router.get("/scans/{id}")
def scan(id: str, db=Depends(session)):
    return row(require(db, Scan, id))

@router.post("/scans/{id}/retry")
def retry(id: str, db=Depends(session)):
    obj = require(db, Scan, id)
    if obj.status != "failed":
        raise HTTPException(409, "Retry is available only for a failed scan")
    obj.status, obj.error, obj.updated_at = "pending", None, now()
    db.commit()
    return row(obj)

class PolicyInput(BaseModel):
    max_critical: int = Field(default=0, ge=0, le=10000)
    max_high: int = Field(default=5, ge=0, le=10000)
    fail_on_secrets: bool = True

def current_policy(db):
    obj = db.get(Policy, "default")
    if obj is None:
        obj = Policy(id="default")
        db.add(obj)
        db.commit()
    return obj

@router.get("/policy")
def get_policy(db=Depends(session)):
    return row(current_policy(db))

@router.put("/policy")
def update_policy(data: PolicyInput, db=Depends(session)):
    obj = current_policy(db)
    obj.max_critical = data.max_critical
    obj.max_high = data.max_high
    obj.fail_on_secrets = int(data.fail_on_secrets)
    obj.updated_at = now()
    db.commit()
    return row(obj)

def evaluate_policy(scan, policy):
    if scan.status != "completed" or not scan.result:
        return {"outcome": "error", "reasons": [f"Scan status is '{scan.status}'. A scan that did not complete must not pass a security gate." + (f" Error: {scan.error}" if scan.error else "")],
                "policy": {"max_critical": policy.max_critical, "max_high": policy.max_high, "fail_on_secrets": bool(policy.fail_on_secrets)}}
    severity = scan.result["summary"].get("severity", {})
    critical, high = severity.get("CRITICAL", 0), severity.get("HIGH", 0)
    secrets = scan.result["summary"].get("secrets", 0)
    reasons = []
    if critical > policy.max_critical:
        reasons.append(f"CRITICAL vulnerabilities: {critical} exceeds the allowed {policy.max_critical}.")
    if high > policy.max_high:
        reasons.append(f"HIGH vulnerabilities: {high} exceeds the allowed {policy.max_high}.")
    if policy.fail_on_secrets and secrets > 0:
        reasons.append(f"Potential secrets found: {secrets}. Review and rotate before deployment.")
    outcome = "fail" if reasons else "pass"
    if not reasons:
        reasons.append(f"Within policy: CRITICAL {critical}/{policy.max_critical}, HIGH {high}/{policy.max_high}, potential secrets {secrets}" + (" (blocking)" if policy.fail_on_secrets else " (not blocking)") + ".")
    return {"outcome": outcome, "reasons": reasons,
            "counts": {"critical": critical, "high": high, "secrets": secrets},
            "policy": {"max_critical": policy.max_critical, "max_high": policy.max_high, "fail_on_secrets": bool(policy.fail_on_secrets)},
            "scanner_version": scan.result.get("metadata", {}).get("scanner_version"),
            "vulnerability_db_updated_at": scan.result.get("metadata", {}).get("vulnerability_db_updated_at")}

@router.get("/scans/{id}/policy")
def scan_policy(id: str, db=Depends(session)):
    scan = require(db, Scan, id)
    return dict(evaluate_policy(scan, current_policy(db)), scan_id=id, filename=scan.filename, digest=scan.digest)

def finding_key(v):
    return f"{v.get('VulnerabilityID')}::{v.get('PkgName')}"

@router.get("/scans/{id}/compare/{other_id}")
def compare_scans(id: str, other_id: str, db=Depends(session)):
    base = require(db, Scan, id)
    target = require(db, Scan, other_id)
    for scan in (base, target):
        if scan.status != "completed" or not scan.result:
            raise HTTPException(409, f"Scan {scan.filename} has status '{scan.status}'. Comparison requires two completed scans.")
    base_findings = {finding_key(v): v for v in base.result["vulnerabilities"]}
    target_findings = {finding_key(v): v for v in target.result["vulnerabilities"]}
    new = [target_findings[k] for k in target_findings.keys() - base_findings.keys()]
    resolved = [base_findings[k] for k in base_findings.keys() - target_findings.keys()]
    remaining = [target_findings[k] for k in target_findings.keys() & base_findings.keys()]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for group in (new, resolved, remaining):
        group.sort(key=lambda v: (order.get(v.get("Severity"), 9), str(v.get("VulnerabilityID"))))
    base_meta = base.result.get("metadata", {})
    target_meta = target.result.get("metadata", {})
    notes = ["Comparison is keyed by CVE and package name within each image.",
             "A resolved finding means it is absent from the rescanned image, not that the fix is deployed. Deployment requires an operator-confirmed deployment record.",
             "New or resolved findings can also result from Trivy vulnerability database updates between scans, not only from image changes."]
    if base_meta.get("scanner_version") != target_meta.get("scanner_version"):
        notes.append(f"Scanner versions differ: {base_meta.get('scanner_version')} vs {target_meta.get('scanner_version')}.")
    if base_meta.get("vulnerability_db_updated_at") != target_meta.get("vulnerability_db_updated_at"):
        notes.append(f"Vulnerability database snapshots differ: {base_meta.get('vulnerability_db_updated_at')} vs {target_meta.get('vulnerability_db_updated_at')}.")
    return {"base": {"id": base.id, "filename": base.filename, "digest": base.digest, "created_at": base.created_at, "metadata": base_meta},
            "target": {"id": target.id, "filename": target.filename, "digest": target.digest, "created_at": target.created_at, "metadata": target_meta},
            "new": new, "resolved": resolved, "remaining": remaining,
            "summary": {"new": len(new), "resolved": len(resolved), "remaining": len(remaining)},
            "notes": notes}

class DeploymentInput(BaseModel):
    service_id: str
    scan_id: str
    started_at: datetime
    ended_at: datetime | None = None
    confirmation: Literal["unverified", "operator_confirmed"]
    evidence: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def check(self):
        if self.started_at.tzinfo is None or (self.ended_at and self.ended_at.tzinfo is None):
            raise ValueError("Specify a timezone")
        if self.ended_at and self.ended_at <= self.started_at:
            raise ValueError("Period end must be after the start")
        if self.confirmation == "operator_confirmed" and not self.evidence.strip():
            raise ValueError("Confirmation requires evidence: a digest or deployment link")
        return self

@router.get("/deployments")
def deployments(db=Depends(session)):
    return [row(x) for x in db.scalars(select(Deployment).order_by(Deployment.started_at.desc()))]

@router.post("/deployments")
def create_deployment(data: DeploymentInput, db=Depends(session)):
    require(db, Service, data.service_id)
    require(db, Scan, data.scan_id)
    values = data.model_dump()
    values["started_at"] = utc(data.started_at)
    values["ended_at"] = utc(data.ended_at) if data.ended_at else None
    obj = Deployment(**values)
    db.add(obj)
    db.commit()
    return row(obj)
