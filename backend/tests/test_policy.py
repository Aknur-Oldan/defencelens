import os
os.environ["DATABASE_URL"] = "sqlite:////tmp/lens-policy-test.db"
os.environ["DATA_DIR"] = "/tmp/lens-test-data"
from types import SimpleNamespace
from app.images import evaluate_policy

POLICY = SimpleNamespace(max_critical=0, max_high=5, fail_on_secrets=1)

def scan(status="completed", critical=0, high=0, secrets=0, error=None):
    result = None
    if status == "completed":
        result = {"summary": {"severity": {"CRITICAL": critical, "HIGH": high}, "secrets": secrets},
                  "metadata": {"scanner_version": "0.61.0", "vulnerability_db_updated_at": "2026-10-03"}}
    return SimpleNamespace(status=status, result=result, error=error)

def test_pass_within_limits():
    verdict = evaluate_policy(scan(high=5), POLICY)
    assert verdict["outcome"] == "pass"
    assert verdict["reasons"]

def test_fail_on_critical():
    verdict = evaluate_policy(scan(critical=1), POLICY)
    assert verdict["outcome"] == "fail"
    assert any("CRITICAL" in r for r in verdict["reasons"])

def test_fail_on_high_above_limit():
    assert evaluate_policy(scan(high=6), POLICY)["outcome"] == "fail"

def test_fail_on_secrets():
    verdict = evaluate_policy(scan(secrets=2), POLICY)
    assert verdict["outcome"] == "fail"
    assert any("secret" in r.lower() for r in verdict["reasons"])

def test_secrets_not_blocking_when_disabled():
    relaxed = SimpleNamespace(max_critical=0, max_high=5, fail_on_secrets=0)
    assert evaluate_policy(scan(secrets=2), relaxed)["outcome"] == "pass"

def test_failed_scan_is_error_never_pass():
    for status in ("pending", "queued", "running", "failed"):
        verdict = evaluate_policy(scan(status=status, error="Trivy: TimeoutExpired"), POLICY)
        assert verdict["outcome"] == "error"
        assert any(status in r for r in verdict["reasons"])
