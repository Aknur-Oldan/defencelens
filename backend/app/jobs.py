import json
import subprocess
from pathlib import Path
from collections import Counter
from app.db import Session
from app.models import Scan, now
from app.config import settings

def scan_image(id):
    with Session() as db:
        scan = db.get(Scan, id)
        if scan is None or scan.status == "completed":
            return
        scan.status, scan.error, scan.updated_at = "running", None, now()
        db.commit()
    try:
        process = subprocess.run(
            ["trivy", "image", "--input", str(Path(settings.data_dir) / "images" / f"{id}.tar"),
             "--scanners", "vuln,secret", "--list-all-pkgs", "--format", "json",
             "--cache-dir", str(Path(settings.data_dir) / "trivy"), "--timeout", "8m", "--quiet"],
            capture_output=True, timeout=510, check=True)
        report = json.loads(process.stdout)
        version = subprocess.run(["trivy", "--version", "--cache-dir", str(Path(settings.data_dir) / "trivy")],
                                 capture_output=True, text=True, timeout=30)
        scanner_version = next((line.split(":", 1)[1].strip() for line in version.stdout.splitlines() if line.startswith("Version:")), "unknown")
        db_updated = next((line.split(":", 1)[1].strip() for line in version.stdout.splitlines() if line.strip().startswith("UpdatedAt:")), "unknown")
        vulns, packages, secrets = [], [], []
        for target in report.get("Results", []):
            for v in target.get("Vulnerabilities", []):
                vulns.append({k: v.get(k) for k in ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Title", "PrimaryURL")})
            for p in target.get("Packages", []):
                packages.append({"name": p.get("Name"), "version": p.get("Version"), "target": target.get("Target")})
            for s in target.get("Secrets", []):
                secrets.append({"rule": s.get("RuleID"), "title": s.get("Title"), "severity": s.get("Severity"), "target": target.get("Target"), "line": s.get("StartLine")})
        result = {"summary": {"vulnerabilities": len(vulns), "components": len(packages), "secrets": len(secrets),
                              "severity": dict(Counter(v["Severity"] for v in vulns))},
                  "vulnerabilities": vulns, "components": packages, "secrets": secrets,
                  "metadata": {"image_id": report.get("Metadata", {}).get("ImageID"), "repo_tags": report.get("Metadata", {}).get("RepoTags", []),
                               "scanner_version": scanner_version, "vulnerability_db_updated_at": db_updated},
                  "limitations": ["A CVE means a known component vulnerability, not proven compromise.", "Results depend on Trivy database coverage and freshness.", "Potential secrets require manual review. Values are hidden.", "An image archive does not automatically include current runtime logs."]}
        with Session() as db:
            scan = db.get(Scan, id)
            scan.status, scan.result, scan.error, scan.updated_at = "completed", result, None, now()
            db.commit()
    except Exception as exc:
        with Session() as db:
            scan = db.get(Scan, id)
            scan.status, scan.error, scan.updated_at = "retrying", f"Trivy: {type(exc).__name__}. Check vulnerability database access, worker resources, and image validity.", now()
            db.commit()
        raise RuntimeError("Trivy scan failed; see persisted diagnostic") from None
