"""SENT-PRIV-001: Unusual Privileged Activity."""

from __future__ import annotations

import re
from collections.abc import Sequence

from app.detection.base import Finding, MitreMapping, RuleConfig, RuleMetadata
from app.detection.windowing import group_events_by, maximal_window
from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import NormalizedEvent

DEFAULT_AUTHORIZED_ADMINS = ["admin", "ops", "secops", "root"]

_SENSITIVE_CMD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("account_manipulation", re.compile(r"\b(useradd|adduser|usermod\s+.*-aG\s+(?:sudo|wheel))\b")),
    ("sudoers_modification", re.compile(r"(/etc/sudoers|/etc/sudoers\.d/|visudo)")),
    ("credential_file_access", re.compile(r"(/etc/shadow|/etc/gshadow)")),
    (
        "history_or_log_tampering",
        re.compile(
            r"(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|rm\s+-[rf]+\s+/var/log|truncate\s+.*var/log)"
        ),
    ),
    (
        "remote_script_execution",
        re.compile(r"\b(curl|wget)\b[^|;]*\|\s*(?:sudo\s+)?(sh|bash|zsh|python)"),
    ),
    ("suid_bit_change", re.compile(r"\bchmod\s+(?:[u+]*s|[2467][0-7]{3})\b")),
)


class PrivilegedActivityRule:
    metadata = RuleMetadata(
        id="SENT-PRIV-001",
        name="Unusual Privileged Activity",
        description=(
            "Detects suspicious privilege elevation and administrative actions: sudo/su "
            "by users outside the authorised admin list, repeated failed sudo attempts, "
            "direct root SSH logins, local account creation, and high-risk command "
            "patterns (shadow access, sudoers edits, history clearing, curl|sh)."
        ),
        category="privilege",
        default_severity=Severity.HIGH,
        default_threshold=3,
        default_time_window_seconds=3600,
        default_parameters={
            "authorized_admins": DEFAULT_AUTHORIZED_ADMINS,
            "allow_root_ssh": False,
            "enforce_business_hours": False,
            "business_hours_start_utc": 7,
            "business_hours_end_utc": 19,
        },
        mitre_mappings=(
            MitreMapping(technique_id="T1548.003", is_primary=True),
            MitreMapping(technique_id="T1078.003", is_primary=False),
            MitreMapping(technique_id="T1136.001", is_primary=False),
            MitreMapping(technique_id="T1070.003", is_primary=False),
            MitreMapping(technique_id="T1105", is_primary=False),
        ),
        investigation_steps=(
            "Confirm with the user or change-management records whether the privileged action was authorised.",
            "Trace the session back to the initial login event and source IP.",
            "Inspect all commands executed in the session for persistence (new users, SSH keys, cron jobs, systemd units).",
        ),
        remediation_steps=(
            "Revoke unauthorized sudo privileges and lock the account if compromise is suspected.",
            "Disable direct root SSH login (`PermitRootLogin no`) and require individual admin accounts before elevating.",
            "Revert unauthorized changes (remove rogue accounts, restore `/etc/sudoers`, rotate exposed credentials).",
        ),
    )
    event_types = frozenset({EventType.AUTHENTICATION, EventType.PROCESS_EXECUTION})

    def evaluate(self, events: Sequence[NormalizedEvent], config: RuleConfig) -> list[Finding]:
        if not config.enabled:
            return []

        authorized = {
            str(u).lower()
            for u in config.parameters.get("authorized_admins", DEFAULT_AUTHORIZED_ADMINS)
        }
        allow_root_ssh = bool(config.parameters.get("allow_root_ssh", False))
        enforce_hours = bool(config.parameters.get("enforce_business_hours", False))
        start_hour = int(config.parameters.get("business_hours_start_utc", 7))
        end_hour = int(config.parameters.get("business_hours_end_utc", 19))

        priv_events = [ev for ev in events if ev.event_type in self.event_types]

        # Group by actor (username or hostname fallback) to produce consolidated findings.
        by_actor = group_events_by(
            priv_events,
            lambda ev: ev.username or str(ev.get("user.target.name") or "") or ev.hostname,
        )

        findings: list[Finding] = []
        for actor, actor_events in by_actor.items():
            matched_events: dict[object, NormalizedEvent] = {}
            reasons: set[str] = set()
            commands: list[str] = []
            escalate_critical = False

            for ev in actor_events:
                user_lower = (ev.username or "").lower()
                cmd = str(ev.get("process.command_line") or "")

                # Condition 1: sudo/su by a user not in authorized_admins
                if (
                    ev.event_action in ("sudo", "su")
                    and ev.username
                    and user_lower not in authorized
                ):
                    reasons.add("unauthorized_user_elevation")
                    matched_events[ev.event_id] = ev
                    if cmd:
                        commands.append(cmd)

                # Condition 2: direct root SSH login
                if (
                    not allow_root_ssh
                    and ev.event_action == "ssh_login"
                    and ev.event_outcome == EventOutcome.SUCCESS
                    and user_lower == "root"
                ):
                    reasons.add("direct_root_ssh_login")
                    matched_events[ev.event_id] = ev

                # Condition 3: local account creation
                if ev.event_action == "user_add":
                    reasons.add("account_manipulation")
                    matched_events[ev.event_id] = ev

                # Condition 4: sensitive command execution
                if cmd:
                    for label, pattern in _SENSITIVE_CMD_PATTERNS:
                        if pattern.search(cmd):
                            reasons.add(label)
                            matched_events[ev.event_id] = ev
                            commands.append(cmd)
                            if label in ("remote_script_execution", "credential_file_access"):
                                escalate_critical = True

                # Condition 5: off-hours privileged action (optional)
                if (
                    enforce_hours
                    and ev.event_action in ("sudo", "su", "user_add")
                    and ev.event_outcome == EventOutcome.SUCCESS
                    and not (start_hour <= ev.timestamp.hour < end_hour)
                ):
                    reasons.add("off_hours_privileged_action")
                    matched_events[ev.event_id] = ev

            # Condition 6: repeated failed sudo/su attempts within the time window
            sudo_failures = [
                ev
                for ev in actor_events
                if ev.event_action in ("sudo", "sudo_auth", "su")
                and ev.event_outcome == EventOutcome.FAILURE
            ]
            failed_burst = maximal_window(
                sudo_failures,
                config.time_window_seconds,
                lambda win: len(win) >= config.threshold,
            )
            if failed_burst:
                reasons.add("repeated_sudo_failures")
                for ev in failed_burst:
                    matched_events[ev.event_id] = ev

            if not reasons:
                continue

            ordered = sorted(matched_events.values(), key=lambda e: e.timestamp)
            severity = Severity.CRITICAL if escalate_critical else config.severity
            hosts = sorted({e.hostname for e in ordered if e.hostname})
            src_ips = sorted({e.source_ip for e in ordered if e.source_ip})
            username = next((e.username for e in ordered if e.username), None)

            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    severity=severity,
                    group_key=f"actor={actor}",
                    title=f"Unusual privileged activity involving '{actor}' ({', '.join(sorted(reasons))})",
                    description=(
                        f"Detected {len(ordered)} privileged security event(s) for '{actor}' "
                        f"matching conditions: {', '.join(sorted(reasons))}."
                    ),
                    mitre_technique_id=self.metadata.primary_technique_id,
                    source_ip=src_ips[0] if len(src_ips) == 1 else None,
                    username=username,
                    hostname=hosts[0] if len(hosts) == 1 else None,
                    evidence={
                        "actor": actor,
                        "triggered_conditions": sorted(reasons),
                        "event_count": len(ordered),
                        "commands": list(dict.fromkeys(commands))[:10],
                        "hosts": hosts[:10],
                        "source_ips": src_ips[:10],
                    },
                    event_ids=[e.event_id for e in ordered],
                    first_seen=ordered[0].timestamp,
                    last_seen=ordered[-1].timestamp,
                )
            )

        return findings
