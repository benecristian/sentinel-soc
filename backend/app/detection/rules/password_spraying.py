"""SENT-AUTH-002: Password Spraying Detection."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import timedelta

from app.detection.base import Finding, MitreMapping, RuleConfig, RuleMetadata
from app.detection.utils import is_ip_allowlisted
from app.detection.windowing import group_events_by, maximal_window
from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import NormalizedEvent


class PasswordSprayingRule:
    metadata = RuleMetadata(
        id="SENT-AUTH-002",
        name="Password Spraying Detection",
        description=(
            "Detects a single source IP failing authentication across many distinct "
            "usernames with few attempts per account (low-and-slow spraying designed "
            "to evade account lockout thresholds)."
        ),
        category="authentication",
        default_severity=Severity.HIGH,
        default_threshold=5,
        default_time_window_seconds=1800,
        default_parameters={"allowlist_ips": [], "max_avg_attempts_per_user": 3.0},
        mitre_mappings=(MitreMapping(technique_id="T1110.003", is_primary=True),),
        investigation_steps=(
            "Determine whether any of the targeted accounts subsequently authenticated successfully from the same IP.",
            "Check whether the targeted usernames follow an enumeration pattern (e.g. alphabetical directory list).",
            "Verify that the source IP is not a shared corporate NAT or VPN concentrator.",
        ),
        remediation_steps=(
            "Block the source IP and enforce multi-factor authentication (MFA) across all remote access services.",
            "Audit targeted accounts for weak or commonly sprayed seasonal passwords.",
            "Enable smart lockout policies that track both per-account and per-source-IP failure rates.",
        ),
    )
    event_types = frozenset({EventType.AUTHENTICATION})

    def evaluate(self, events: Sequence[NormalizedEvent], config: RuleConfig) -> list[Finding]:
        if not config.enabled:
            return []

        allowlist: list[str] = list(config.parameters.get("allowlist_ips", []))
        max_avg = float(config.parameters.get("max_avg_attempts_per_user", 3.0))

        auth_events = [
            ev
            for ev in events
            if ev.event_type == EventType.AUTHENTICATION
            and ev.event_action != "ssh_invalid_user"
            and ev.source_ip
            and ev.username
            and not is_ip_allowlisted(ev.source_ip, allowlist)
        ]
        failures_by_ip = group_events_by(
            [ev for ev in auth_events if ev.event_outcome == EventOutcome.FAILURE],
            lambda ev: ev.source_ip,
        )
        successes_by_ip = group_events_by(
            [ev for ev in auth_events if ev.event_outcome == EventOutcome.SUCCESS],
            lambda ev: ev.source_ip,
        )

        def _is_spray(window: Sequence[NormalizedEvent]) -> bool:
            users = {ev.username for ev in window if ev.username}
            if len(users) < config.threshold:
                return False
            avg_attempts = len(window) / len(users)
            return avg_attempts <= max_avg

        findings: list[Finding] = []
        for src_ip, ip_failures in failures_by_ip.items():
            matched = maximal_window(ip_failures, config.time_window_seconds, _is_spray)
            if not matched or not _is_spray(matched):
                continue

            first_seen = matched[0].timestamp
            last_seen = matched[-1].timestamp
            per_user = Counter(ev.username for ev in matched if ev.username)
            avg_attempts = round(len(matched) / len(per_user), 2)

            horizon = last_seen + timedelta(seconds=config.time_window_seconds)
            successes = [
                ev
                for ev in successes_by_ip.get(src_ip, [])
                if first_seen <= ev.timestamp <= horizon
            ]
            compromise_suspected = bool(successes)
            severity = Severity.CRITICAL if compromise_suspected else config.severity
            all_events = [*matched, *successes]
            services = sorted({ev.service for ev in matched if ev.service})
            hosts = sorted({ev.hostname for ev in matched if ev.hostname})

            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    severity=severity,
                    group_key=f"src_ip={src_ip}",
                    title=(
                        f"Password spraying from {src_ip} across {len(per_user)} accounts"
                        + (" (followed by login success)" if compromise_suspected else "")
                    ),
                    description=(
                        f"Source IP {src_ip} failed authentication against {len(per_user)} "
                        f"distinct usernames ({len(matched)} total attempts, {avg_attempts} "
                        f"avg/user) within {int((last_seen - first_seen).total_seconds())}s."
                    ),
                    mitre_technique_id=self.metadata.primary_technique_id,
                    source_ip=src_ip,
                    hostname=hosts[0] if len(hosts) == 1 else None,
                    evidence={
                        "distinct_usernames_count": len(per_user),
                        "total_failed_attempts": len(matched),
                        "avg_attempts_per_user": avg_attempts,
                        "attempts_by_username": dict(per_user.most_common(15)),
                        "services": services,
                        "targeted_hosts": hosts[:10],
                        "compromise_suspected": compromise_suspected,
                        "successful_logins": [
                            {"username": ev.username, "timestamp": ev.timestamp.isoformat()}
                            for ev in successes[:5]
                        ],
                    },
                    event_ids=[ev.event_id for ev in all_events],
                    first_seen=first_seen,
                    last_seen=max(ev.timestamp for ev in all_events),
                )
            )

        return findings
