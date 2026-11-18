"""End-to-end API and PostgreSQL integration tests."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from alembic.config import Config
from fastapi.testclient import TestClient

from alembic import command
from tests.conftest import CSRF_HEADERS, TEST_PASSWORD, login_as

pytestmark = pytest.mark.db


def test_health_and_security_headers(api_client: TestClient) -> None:
    r1 = api_client.get("/api/v1/health")
    assert r1.status_code == 200
    assert r1.json()["status"] == "ok"
    assert r1.headers["X-Content-Type-Options"] == "nosniff"
    assert r1.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r1.headers["Content-Security-Policy"]
    assert "X-Request-ID" in r1.headers

    # Unversioned /api/health alias also works
    r2 = api_client.get("/api/health/ready")
    assert r2.status_code == 200
    assert r2.json()["database"] == "ok"


def test_authentication_csrf_and_rbac(api_client: TestClient) -> None:
    # Unauthenticated access is rejected with 401
    assert api_client.get("/api/v1/alerts").status_code == 401

    # State-changing request without CSRF header is rejected with 403
    no_csrf = api_client.post(
        "/api/v1/auth/login", json={"username": "analyst", "password": TEST_PASSWORD}
    )
    assert no_csrf.status_code == 403
    assert no_csrf.json()["error"]["code"] == "csrf_check_failed"

    # Invalid password returns generic 401 and does not echo password
    bad = api_client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "WrongPassword999"},
        headers=CSRF_HEADERS,
    )
    assert bad.status_code == 401
    assert "WrongPassword999" not in bad.text

    # Login as viewer: can read rules, cannot run simulations or patch rules
    login_as(api_client, "viewer")
    assert api_client.get("/api/v1/detections/rules").status_code == 200
    assert (
        api_client.post("/api/v1/simulations/normal_activity/run", headers=CSRF_HEADERS).status_code
        == 403
    )

    # Login as analyst: can run simulations, but cannot PATCH detection rule config (admin only)
    login_as(api_client, "analyst")
    assert (
        api_client.patch(
            "/api/v1/detections/rules/SENT-AUTH-001",
            json={"threshold": 15},
            headers=CSRF_HEADERS,
        ).status_code
        == 403
    )

    # Login as admin: can PATCH detection rule config
    login_as(api_client, "admin")
    patch_resp = api_client.patch(
        "/api/v1/detections/rules/SENT-AUTH-001",
        json={"threshold": 12, "parameters": {"allowlist_ips": ["10.99.0.0/16"]}},
        headers=CSRF_HEADERS,
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["threshold"] == 12
    assert patch_resp.json()["version"] == 2


def test_upload_validation_and_idempotent_ingestion(api_client: TestClient) -> None:
    login_as(api_client, "analyst")

    # 1. Reject unsupported file extension
    bad_ext = api_client.post(
        "/api/v1/events/upload",
        files={"file": ("malware.exe", b"hello", "application/octet-stream")},
        data={"format": "auto"},
        headers=CSRF_HEADERS,
    )
    assert bad_ext.status_code == 415

    # 2. Reject binary file containing NUL bytes disguised as .log
    nul_resp = api_client.post(
        "/api/v1/events/upload",
        files={"file": ("binary.log", b"Nov 16 10:00:00 h sshd: \x00binary", "text/plain")},
        data={"format": "auto"},
        headers=CSRF_HEADERS,
    )
    assert nul_resp.status_code == 415

    # 3. Upload synthetic auth.log + one malformed line -> triggers SENT-AUTH-001
    sample_path = Path(__file__).resolve().parents[2] / "sample_logs" / "synthetic_auth.log"
    content = sample_path.read_text(encoding="utf-8") + "\nTHIS_LINE_IS_MALFORMED\n"
    up1 = api_client.post(
        "/api/v1/events/upload",
        files={"file": ("synthetic_auth.log", io.BytesIO(content.encode("utf-8")), "text/plain")},
        data={"format": "linux_auth"},
        headers=CSRF_HEADERS,
    )
    assert up1.status_code == 201, up1.text
    b1 = up1.json()
    assert b1["accepted_count"] == 12
    assert b1["rejected_count"] == 1
    assert b1["alerts_created"] >= 1

    # 4. Re-uploading the exact same file is idempotent: 0 newly accepted, 12 duplicates
    up2 = api_client.post(
        "/api/v1/events/upload",
        files={"file": ("synthetic_auth.log", io.BytesIO(content.encode("utf-8")), "text/plain")},
        data={"format": "linux_auth"},
        headers=CSRF_HEADERS,
    )
    assert up2.status_code == 201
    b2 = up2.json()
    assert b2["accepted_count"] == 0
    assert b2["duplicate_count"] == 12
    assert b2["alerts_created"] == 0


def test_simulations_alert_lifecycle_incident_workflow_and_reports(
    api_client: TestClient,
) -> None:
    login_as(api_client, "analyst")

    # 1. Benign simulation produces 0 alerts
    r_benign = api_client.post(
        "/api/v1/simulations/normal_activity/run",
        json={"seed": 1001},
        headers=CSRF_HEADERS,
    )
    assert r_benign.status_code == 201
    assert r_benign.json()["events_generated"] >= 15
    assert r_benign.json()["alerts_generated"] == 0

    # 2. Multi-stage attack simulation generates alerts across multiple rules
    r_attack = api_client.post(
        "/api/v1/simulations/multi_stage_attack/run",
        json={"seed": 2007},
        headers=CSRF_HEADERS,
    )
    assert r_attack.status_code == 201
    assert r_attack.json()["alerts_generated"] >= 4

    alerts_page = api_client.get("/api/v1/alerts").json()
    assert alerts_page["total"] >= 4
    first_alert = alerts_page["items"][0]
    alert_id = first_alert["id"]

    # 3. Alert lifecycle: closing without a note fails (422)
    close_no_note = api_client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"status": "resolved"},
        headers=CSRF_HEADERS,
    )
    assert close_no_note.status_code == 422

    # Transition new -> investigating -> resolved with a note (including XSS test payload)
    triage_resp = api_client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"status": "investigating", "note": "Investigating <script>alert(1)</script>"},
        headers=CSRF_HEADERS,
    )
    assert triage_resp.status_code == 200
    assert triage_resp.json()["status"] == "investigating"
    assert len(triage_resp.json()["notes"]) == 1

    resolve_resp = api_client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"status": "resolved"},
        headers=CSRF_HEADERS,
    )
    assert resolve_resp.status_code == 200
    assert resolve_resp.json()["status"] == "resolved"
    assert resolve_resp.json()["resolved_at"] is not None

    # Invalid transition resolved -> false_positive is rejected with 409
    bad_transition = api_client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"status": "false_positive"},
        headers=CSRF_HEADERS,
    )
    assert bad_transition.status_code == 409

    # 4. Create an Incident grouping two alerts
    alert_ids = [a["id"] for a in alerts_page["items"][:2]]
    inc_resp = api_client.post(
        "/api/v1/incidents",
        json={
            "title": "Multi-Stage Intrusion on app-srv-01",
            "description": "Coordinated port scan, SSH brute force, sudo abuse and DNS exfil.",
            "severity": "critical",
            "alert_ids": alert_ids,
        },
        headers=CSRF_HEADERS,
    )
    assert inc_resp.status_code == 201, inc_resp.text
    incident = inc_resp.json()
    incident_id = incident["id"]
    assert incident["alert_count"] == 2
    assert len(incident["timeline"]) >= 3

    # Attempting to attach the same alert to a second incident fails with 409
    dup_inc = api_client.post(
        "/api/v1/incidents",
        json={"title": "Duplicate Incident", "severity": "high", "alert_ids": [alert_ids[0]]},
        headers=CSRF_HEADERS,
    )
    assert dup_inc.status_code == 409

    # Invalid incident state jump open -> recovery fails with 409
    assert (
        api_client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": "recovery"},
            headers=CSRF_HEADERS,
        ).status_code
        == 409
    )

    # Valid workflow: open -> containment + add note
    assert (
        api_client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": "containment", "findings": "Isolated host 10.0.1.20 <bold>test</bold>"},
            headers=CSRF_HEADERS,
        ).status_code
        == 200
    )
    note_resp = api_client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"body": "Blocked 203.0.113.200 at fw-edge-01 & rotated keys."},
        headers=CSRF_HEADERS,
    )
    assert note_resp.status_code == 201

    # 5. Generate JSON and PDF incident reports
    json_rep = api_client.get(f"/api/v1/reports/incidents/{incident_id}")
    assert json_rep.status_code == 200
    assert json_rep.json()["report_metadata"]["contains_synthetic_data"] is True
    assert len(json_rep.json()["related_alerts"]) == 2

    pdf_rep = api_client.get(f"/api/v1/reports/incidents/{incident_id}/pdf")
    assert pdf_rep.status_code == 200
    assert pdf_rep.headers["content-type"] == "application/pdf"
    assert pdf_rep.content.startswith(b"%PDF-")

    # 6. Verify Dashboard, MITRE Coverage & Threat Hunting endpoints
    dash = api_client.get("/api/v1/dashboard/overview").json()
    assert dash["kpis"]["total_events"] >= 40
    assert dash["kpis"]["open_incidents"] == 1

    cov = api_client.get("/api/v1/mitre/coverage").json()
    assert cov["summary"]["implemented_count"] >= 7
    assert cov["summary"]["documented_count"] >= 5

    # CIDR hunt filter + SQL injection literal test
    cidr_res = api_client.get("/api/v1/hunting/search?cidr=203.0.113.0/24").json()
    assert cidr_res["total"] >= 10
    sqli_res = api_client.get("/api/v1/hunting/search?q=' OR 1=1 --").json()
    assert sqli_res["total"] == 0

    ip_pivot = api_client.get("/api/v1/hunting/entities/ip/203.0.113.200").json()
    assert ip_pivot["total_events"] >= 10
    user_pivot = api_client.get("/api/v1/hunting/entities/user/webadmin").json()
    assert user_pivot["total_events"] >= 10

    for hunt_id in (
        "compromised_after_failures",
        "multi_category_sources",
        "high_entropy_dns_hunt",
        "suspicious_privilege_commands",
    ):
        hunt_run = api_client.post(f"/api/v1/hunting/queries/{hunt_id}/run", headers=CSRF_HEADERS)
        assert hunt_run.status_code == 200
        assert hunt_run.json()["total_results"] >= 1


def test_alembic_migrations_upgrade_downgrade_roundtrip(test_db_url: str) -> None:
    backend_root = Path(__file__).resolve().parents[2]
    cfg = Config()
    cfg.attributes["configure_logger"] = False
    cfg.set_main_option("script_location", str(backend_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", test_db_url)

    command.stamp(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
