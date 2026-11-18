"""SENT-NET-001: Port Scanning Detection."""

from __future__ import annotations

from collections.abc import Sequence

from app.detection.base import Finding, MitreMapping, RuleConfig, RuleMetadata
from app.detection.utils import is_ip_allowlisted
from app.detection.windowing import group_events_by, maximal_window
from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import NormalizedEvent


class PortScanningRule:
    metadata = RuleMetadata(
        id="SENT-NET-001",
        name="Port Scanning Detection",
        description=(
            "Detects a source IP probing many distinct destination ports on a target "
            "host within a short window (vertical port scan), or sweeping a single port "
            "across many hosts (horizontal scan)."
        ),
        category="network",
        default_severity=Severity.MEDIUM,
        default_threshold=20,
        default_time_window_seconds=60,
        default_parameters={"allowlist_ips": [], "horizontal_host_threshold": 15},
        mitre_mappings=(
            MitreMapping(technique_id="T1046", is_primary=True),
            MitreMapping(technique_id="T1595.001", is_primary=False),
        ),
        investigation_steps=(
            "Determine whether the source IP is external (internet reconnaissance) or internal (possible lateral movement discovery).",
            "Check whether any of the probed ports were allowed through the firewall (`allowed_connections > 0`).",
            "Correlate the source IP with authentication or web alerts that followed the scan.",
            "Confirm the source IP is not an authorised vulnerability scanner.",
        ),
        remediation_steps=(
            "Block external scanning IPs at the perimeter firewall.",
            "If the source is an internal workstation or server, isolate the host and investigate for compromise.",
            "Add authorised scanner IPs to the rule allowlist so legitimate scans do not cause alert fatigue.",
        ),
    )
    event_types = frozenset({EventType.FIREWALL, EventType.NETWORK_CONNECTION})

    def evaluate(self, events: Sequence[NormalizedEvent], config: RuleConfig) -> list[Finding]:
        if not config.enabled:
            return []

        allowlist: list[str] = list(config.parameters.get("allowlist_ips", []))
        horizontal_threshold = int(config.parameters.get("horizontal_host_threshold", 15))

        candidates = [
            ev
            for ev in events
            if ev.event_type in self.event_types
            and ev.source_ip
            and ev.destination_ip
            and ev.destination_port is not None
            and not is_ip_allowlisted(ev.source_ip, allowlist)
        ]

        findings: list[Finding] = []

        # 1. Vertical scan: (source_ip, destination_ip) -> many destination ports
        by_pair = group_events_by(
            candidates, lambda ev: (ev.source_ip or "", ev.destination_ip or "")
        )
        for (src_ip, dst_ip), pair_events in by_pair.items():
            matched = maximal_window(
                pair_events,
                config.time_window_seconds,
                lambda win: (
                    len({e.destination_port for e in win if e.destination_port is not None})
                    >= config.threshold
                ),
            )
            if not matched:
                continue

            ports = sorted({e.destination_port for e in matched if e.destination_port is not None})
            allowed_count = sum(1 for e in matched if e.event_outcome == EventOutcome.SUCCESS)
            blocked_count = sum(1 for e in matched if e.event_outcome == EventOutcome.FAILURE)
            protocols = sorted({e.protocol for e in matched if e.protocol})
            first_seen = matched[0].timestamp
            last_seen = matched[-1].timestamp

            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    severity=config.severity,
                    group_key=f"vertical:{src_ip}->{dst_ip}",
                    title=f"Port scan from {src_ip} against {dst_ip} ({len(ports)} ports)",
                    description=(
                        f"Source IP {src_ip} probed {len(ports)} distinct destination ports on "
                        f"{dst_ip} within {int((last_seen - first_seen).total_seconds())}s "
                        f"({blocked_count} blocked, {allowed_count} allowed)."
                    ),
                    mitre_technique_id=self.metadata.primary_technique_id,
                    source_ip=src_ip,
                    hostname=matched[0].hostname,
                    evidence={
                        "scan_type": "vertical",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "distinct_ports_count": len(ports),
                        "sampled_ports": ports[:30],
                        "total_packets": len(matched),
                        "allowed_connections": allowed_count,
                        "blocked_connections": blocked_count,
                        "protocols": protocols,
                    },
                    event_ids=[e.event_id for e in matched],
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

        # 2. Horizontal sweep: (source_ip, destination_port) -> many destination hosts
        if horizontal_threshold > 0:
            by_src_port = group_events_by(
                candidates, lambda ev: (ev.source_ip or "", int(ev.destination_port or 0))
            )
            for (src_ip, dst_port), port_events in by_src_port.items():
                matched = maximal_window(
                    port_events,
                    config.time_window_seconds,
                    lambda win: (
                        len({e.destination_ip for e in win if e.destination_ip})
                        >= horizontal_threshold
                    ),
                )
                if not matched:
                    continue
                hosts = sorted({e.destination_ip for e in matched if e.destination_ip})
                first_seen = matched[0].timestamp
                last_seen = matched[-1].timestamp
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=config.severity,
                        group_key=f"horizontal:{src_ip}:{dst_port}",
                        title=f"Horizontal port sweep from {src_ip} on port {dst_port} ({len(hosts)} hosts)",
                        description=(
                            f"Source IP {src_ip} probed port {dst_port} across {len(hosts)} "
                            f"distinct hosts within {int((last_seen - first_seen).total_seconds())}s."
                        ),
                        mitre_technique_id=self.metadata.primary_technique_id,
                        source_ip=src_ip,
                        evidence={
                            "scan_type": "horizontal",
                            "source_ip": src_ip,
                            "destination_port": dst_port,
                            "distinct_hosts_count": len(hosts),
                            "sampled_hosts": hosts[:25],
                            "total_packets": len(matched),
                        },
                        event_ids=[e.event_id for e in matched],
                        first_seen=first_seen,
                        last_seen=last_seen,
                    )
                )

        return findings
