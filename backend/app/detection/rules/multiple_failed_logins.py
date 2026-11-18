"""SENT-AUTH-003: Multiple Failed Logins (Single Account)."""

from __future__ import annotations

from collections.abc import Sequence

from app.detection.base import Finding, MitreMapping, RuleConfig, RuleMetadata
from app.detection.utils import is_ip_allowlisted
from app.detection.windowing import group_events_by, maximal_window
from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import NormalizedEvent


class MultipleFailedLoginsRule:
    metadata = RuleMetadata(
        id="SENT-AUTH-003",
        name="Multiple Failed Logins (Single Account)",
        description=(
            "Detects repeated authentication failures targeting a single user account "
            "regardless of source IP, catching distributed attacks or targeted account "
            "lockout/guessing attempts."
        ),
        category="authentication",
        default_severity=Severity.MEDIUM,
        default_threshold=5,
        default_time_window_seconds=900,
        default_parameters={"allowlist_ips": [], "distributed_ip_threshold": 3},
        mitre_mappings=(MitreMapping(technique_id="T1110.001", is_primary=True),),
        investigation_steps=(
            "Check whether failures originate from one IP (single source) or many IPs (distributed attack).",
            "Contact the account owner or check service dependencies to rule out a misconfigured client.",
            "Verify whether a successful authentication occurred after the failures.",
        ),
        remediation_steps=(
            "Enforce MFA and temporary account lockout after repeated failures.",
            "If the failures are distributed across external IPs, restrict login sources or require VPN.",
            "Reset the user's password if compromise is suspected.",
        ),
    )
    event_types = frozenset({EventType.AUTHENTICATION})

    def evaluate(self, events: Sequence[NormalizedEvent], config: RuleConfig) -> list[Finding]:
        if not config.enabled:
            return []

        allowlist: list[str] = list(config.parameters.get("allowlist_ips", []))
        distributed_threshold = int(config.parameters.get("distributed_ip_threshold", 3))

        failures = [
            ev
            for ev in events
            if ev.event_type == EventType.AUTHENTICATION
            and ev.event_outcome == EventOutcome.FAILURE
            and ev.event_action != "ssh_invalid_user"
            and ev.username
            and not is_ip_allowlisted(ev.source_ip, allowlist)
        ]
        by_user = group_events_by(failures, lambda ev: ev.username)

        findings: list[Finding] = []
        for username, user_failures in by_user.items():
            matched = maximal_window(
                user_failures,
                config.time_window_seconds,
                lambda win: len(win) >= config.threshold,
            )
            if not matched:
                continue

            first_seen = matched[0].timestamp
            last_seen = matched[-1].timestamp
            source_ips = sorted({ev.source_ip for ev in matched if ev.source_ip})
            hosts = sorted({ev.hostname for ev in matched if ev.hostname})
            services = sorted({ev.service for ev in matched if ev.service})

            is_distributed = len(source_ips) >= distributed_threshold
            severity = (
                Severity.HIGH
                if is_distributed and config.severity.rank < Severity.HIGH.rank
                else config.severity
            )

            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    severity=severity,
                    group_key=f"username={username}",
                    title=(
                        f"Repeated authentication failures for account '{username}' "
                        f"({len(matched)} failures across {len(source_ips) or 1} source(s))"
                    ),
                    description=(
                        f"Account '{username}' experienced {len(matched)} failed login attempts "
                        f"from {len(source_ips) or 1} distinct source IP(s) within "
                        f"{int((last_seen - first_seen).total_seconds())}s."
                    ),
                    mitre_technique_id=self.metadata.primary_technique_id,
                    source_ip=source_ips[0] if len(source_ips) == 1 else None,
                    username=username,
                    hostname=hosts[0] if len(hosts) == 1 else None,
                    evidence={
                        "username": username,
                        "failed_attempt_count": len(matched),
                        "distinct_source_ips": len(source_ips),
                        "source_ips": source_ips[:15],
                        "distributed_attack": is_distributed,
                        "services": services,
                        "targeted_hosts": hosts[:10],
                    },
                    event_ids=[ev.event_id for ev in matched],
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

        return findings
