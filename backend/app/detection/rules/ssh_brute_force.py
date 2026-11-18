"""SENT-AUTH-001: SSH Brute Force Detection."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import timedelta

from app.detection.base import Finding, MitreMapping, RuleConfig, RuleMetadata
from app.detection.utils import is_ip_allowlisted
from app.detection.windowing import group_events_by, maximal_window
from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import NormalizedEvent


def _is_ssh_auth(ev: NormalizedEvent) -> bool:
    if ev.event_type != EventType.AUTHENTICATION:
        return False
    if ev.event_action == "ssh_invalid_user":
        return False
    return ev.service == "sshd" or ev.protocol == "ssh" or ev.event_action == "ssh_login"


class SshBruteForceRule:
    metadata = RuleMetadata(
        id="SENT-AUTH-001",
        name="SSH Brute Force Detection",
        description=(
            "Detects repeated failed SSH authentication attempts from a single source IP "
            "within a short time window, indicative of automated password guessing."
        ),
        category="authentication",
        default_severity=Severity.HIGH,
        default_threshold=10,
        default_time_window_seconds=300,
        default_parameters={"allowlist_ips": [], "escalate_on_success": True},
        mitre_mappings=(
            MitreMapping(technique_id="T1110.001", is_primary=True),
            MitreMapping(technique_id="T1021.004", is_primary=False),
        ),
        investigation_steps=(
            "Check whether any SSH login from the source IP succeeded during or after the burst.",
            "Identify which user accounts were targeted and whether they are valid local or directory accounts.",
            "Inspect other telemetry (firewall, web, DNS) for activity involving the same source IP.",
            "Verify whether the source IP belongs to an internal automation host with a stale credential.",
        ),
        remediation_steps=(
            "Block the offending source IP at the perimeter firewall or host firewall.",
            "Disable SSH password authentication (`PasswordAuthentication no`) in favour of SSH keys.",
            "Disable direct root SSH login (`PermitRootLogin no`) and deploy rate limiting (e.g. fail2ban).",
            "If a subsequent login succeeded, isolate the target host and rotate the affected credentials immediately.",
        ),
    )
    event_types = frozenset({EventType.AUTHENTICATION})

    def evaluate(self, events: Sequence[NormalizedEvent], config: RuleConfig) -> list[Finding]:
        if not config.enabled:
            return []

        allowlist: list[str] = list(config.parameters.get("allowlist_ips", []))
        escalate_on_success = bool(config.parameters.get("escalate_on_success", True))

        ssh_events = [
            ev
            for ev in events
            if _is_ssh_auth(ev) and ev.source_ip and not is_ip_allowlisted(ev.source_ip, allowlist)
        ]
        failures_by_ip = group_events_by(
            [ev for ev in ssh_events if ev.event_outcome == EventOutcome.FAILURE],
            lambda ev: ev.source_ip,
        )
        successes_by_ip = group_events_by(
            [ev for ev in ssh_events if ev.event_outcome == EventOutcome.SUCCESS],
            lambda ev: ev.source_ip,
        )

        findings: list[Finding] = []
        for src_ip, ip_failures in failures_by_ip.items():
            matched = maximal_window(
                ip_failures,
                config.time_window_seconds,
                lambda win: len(win) >= config.threshold,
            )
            if not matched:
                continue

            first_seen = matched[0].timestamp
            last_seen = matched[-1].timestamp
            follow_up_horizon = last_seen + timedelta(seconds=config.time_window_seconds)
            success_events = [
                ev
                for ev in successes_by_ip.get(src_ip, [])
                if first_seen <= ev.timestamp <= follow_up_horizon
            ]

            compromise_suspected = bool(success_events)
            severity = (
                Severity.CRITICAL
                if compromise_suspected and escalate_on_success
                else config.severity
            )

            all_matched = [*matched, *success_events]
            last_seen_all = max(ev.timestamp for ev in all_matched)
            user_counts = Counter(ev.username for ev in matched if ev.username)
            targeted_hosts = sorted({ev.hostname for ev in matched if ev.hostname})
            top_user = user_counts.most_common(1)[0][0] if user_counts else None

            title = (
                f"SSH brute force from {src_ip} followed by successful login"
                if compromise_suspected
                else f"SSH brute force detected from {src_ip} ({len(matched)} failed attempts)"
            )
            description = (
                f"Source IP {src_ip} generated {len(matched)} failed SSH login attempts within "
                f"{int((last_seen - first_seen).total_seconds())}s "
                f"(threshold: {config.threshold} in {config.time_window_seconds}s)."
            )
            if compromise_suspected:
                succeeded_users = sorted({ev.username or "unknown" for ev in success_events})
                description += (
                    f" A subsequent SSH login SUCCEEDED for: {', '.join(succeeded_users)}."
                )

            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    severity=severity,
                    group_key=f"src_ip={src_ip}",
                    title=title,
                    description=description,
                    mitre_technique_id=self.metadata.primary_technique_id,
                    source_ip=src_ip,
                    username=top_user,
                    hostname=targeted_hosts[0] if len(targeted_hosts) == 1 else None,
                    evidence={
                        "failed_attempt_count": len(matched),
                        "distinct_usernames_count": len(user_counts),
                        "targeted_usernames": [u for u, _ in user_counts.most_common(10)],
                        "targeted_hosts": targeted_hosts[:10],
                        "window_seconds": round((last_seen - first_seen).total_seconds(), 2),
                        "compromise_suspected": compromise_suspected,
                        "successful_logins": [
                            {
                                "username": ev.username,
                                "timestamp": ev.timestamp.isoformat(),
                                "event_id": str(ev.event_id),
                            }
                            for ev in success_events[:5]
                        ],
                    },
                    event_ids=[ev.event_id for ev in all_matched],
                    first_seen=first_seen,
                    last_seen=last_seen_all,
                )
            )

        return findings
