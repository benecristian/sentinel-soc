"""SENT-DNS-001: Suspicious DNS Activity."""

from __future__ import annotations

from collections.abc import Sequence

from app.detection.base import Finding, MitreMapping, RuleConfig, RuleMetadata
from app.detection.utils import (
    is_domain_allowlisted,
    is_ip_allowlisted,
    shannon_entropy,
    split_domain,
)
from app.detection.windowing import group_events_by, maximal_window
from app.domain.enums import EventType, Severity
from app.domain.events import NormalizedEvent

DEFAULT_DOMAIN_ALLOWLIST = [
    "amazonaws.com",
    "cloudfront.net",
    "akadns.net",
    "akamaiedge.net",
    "azure.com",
    "microsoft.com",
    "office.com",
    "googleapis.com",
    "gstatic.com",
]


class SuspiciousDnsRule:
    metadata = RuleMetadata(
        id="SENT-DNS-001",
        name="Suspicious DNS Activity",
        description=(
            "Detects DNS queries with characteristics of DNS tunneling, data exfiltration "
            "or domain generation algorithms (DGA): unusually long query names or labels, "
            "high-entropy subdomains, suspicious TLDs, or high-volume unique subdomain "
            "queries to a single parent domain."
        ),
        category="dns",
        default_severity=Severity.MEDIUM,
        default_threshold=50,
        default_time_window_seconds=600,
        default_parameters={
            "allowlist_ips": [],
            "domain_allowlist": DEFAULT_DOMAIN_ALLOWLIST,
            "max_query_length": 75,
            "max_label_length": 50,
            "entropy_threshold": 3.8,
            "min_entropy_length": 20,
            "suspicious_tlds": ["zip", "mov", "top", "xyz", "tk", "gq", "cf", "ml"],
        },
        mitre_mappings=(
            MitreMapping(technique_id="T1071.004", is_primary=True),
            MitreMapping(technique_id="T1568.002", is_primary=False),
            MitreMapping(technique_id="T1048", is_primary=False),
        ),
        investigation_steps=(
            "Inspect the queried subdomain labels: base32/base64/hex-encoded chunks strongly suggest DNS tunneling or exfiltration.",
            "Identify the process on the source host that generated the DNS queries.",
            "Check domain registration age and authoritative nameservers in external threat intelligence.",
            "Verify whether the domain belongs to a legitimate CDN, anti-virus or cloud telemetry service.",
        ),
        remediation_steps=(
            "Sinkhole or block the parent domain at the internal DNS resolver.",
            "Isolate the querying host and inspect it for C2 agents or data-exfiltration scripts.",
            "Restrict outbound port 53/UDP and 53/TCP so hosts can only query corporate DNS resolvers.",
        ),
    )
    event_types = frozenset({EventType.DNS_QUERY})

    def evaluate(self, events: Sequence[NormalizedEvent], config: RuleConfig) -> list[Finding]:
        if not config.enabled:
            return []

        allowlist_ips: list[str] = list(config.parameters.get("allowlist_ips", []))
        domain_allowlist: list[str] = list(
            config.parameters.get("domain_allowlist", DEFAULT_DOMAIN_ALLOWLIST)
        )
        max_query_len = int(config.parameters.get("max_query_length", 75))
        max_label_len = int(config.parameters.get("max_label_length", 50))
        entropy_threshold = float(config.parameters.get("entropy_threshold", 3.8))
        min_entropy_len = int(config.parameters.get("min_entropy_length", 20))
        suspicious_tlds = {
            str(t).lower().lstrip(".") for t in config.parameters.get("suspicious_tlds", [])
        }

        dns_events = [
            ev
            for ev in events
            if ev.event_type == EventType.DNS_QUERY
            and ev.source_ip
            and not is_ip_allowlisted(ev.source_ip, allowlist_ips)
            and isinstance(ev.get("dns.question.name"), str)
            and not is_domain_allowlisted(str(ev.get("dns.question.name")), domain_allowlist)
        ]

        # Group by (source_ip, registered_domain) so alerts are consolidated per domain.
        def _group_key(ev: NormalizedEvent) -> tuple[str, str] | None:
            qname = str(ev.get("dns.question.name", ""))
            _, reg_domain, _ = split_domain(qname)
            if not ev.source_ip or not reg_domain:
                return None
            return (ev.source_ip, reg_domain)

        grouped = group_events_by(dns_events, _group_key)
        findings: list[Finding] = []

        for (src_ip, reg_domain), group in grouped.items():
            flagged_events: list[NormalizedEvent] = []
            indicators: set[str] = set()
            max_observed_entropy = 0.0
            max_observed_len = 0

            for ev in group:
                qname = str(ev.get("dns.question.name", "")).rstrip(".")
                subdomain, _, suffix = split_domain(qname)
                labels = qname.split(".")
                longest_label = max((len(lbl) for lbl in labels), default=0)
                sub_compact = subdomain.replace(".", "")
                ent = shannon_entropy(sub_compact)

                ev_hit = False
                if len(qname) > max_query_len:
                    indicators.add("excessive_query_length")
                    ev_hit = True
                if longest_label > max_label_len:
                    indicators.add("excessive_label_length")
                    ev_hit = True
                if len(sub_compact) >= min_entropy_len and ent > entropy_threshold:
                    indicators.add("high_entropy_subdomain")
                    ev_hit = True
                if suffix in suspicious_tlds:
                    indicators.add("suspicious_tld")
                    ev_hit = True

                if ev_hit:
                    flagged_events.append(ev)
                    max_observed_entropy = max(max_observed_entropy, ent)
                    max_observed_len = max(max_observed_len, len(qname))

            # Volume check: many distinct subdomains within the window (DNS tunneling).
            volume_window = maximal_window(
                group,
                config.time_window_seconds,
                lambda win: (
                    len({split_domain(str(e.get("dns.question.name", "")))[0] for e in win} - {""})
                    >= config.threshold
                ),
            )
            if volume_window:
                indicators.add("high_subdomain_volume")

            if not indicators:
                continue

            combined_map = {ev.event_id: ev for ev in [*flagged_events, *(volume_window or [])]}
            matched = sorted(combined_map.values(), key=lambda e: e.timestamp)
            unique_subdomains = sorted(
                {
                    split_domain(str(e.get("dns.question.name", "")))[0]
                    for e in matched
                    if split_domain(str(e.get("dns.question.name", "")))[0]
                }
            )
            qtypes = sorted({str(e.get("dns.question.type", "A")) for e in matched})

            severity = (
                Severity.HIGH
                if "high_subdomain_volume" in indicators
                or ("high_entropy_subdomain" in indicators and len(flagged_events) >= 5)
                else config.severity
            )

            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    severity=severity,
                    group_key=f"src_ip={src_ip}:domain={reg_domain}",
                    title=f"Suspicious DNS queries from {src_ip} to *.{reg_domain}",
                    description=(
                        f"Host {src_ip} issued {len(matched)} suspicious DNS query/queries under "
                        f"'{reg_domain}' matching indicators: {', '.join(sorted(indicators))}."
                    ),
                    mitre_technique_id=self.metadata.primary_technique_id,
                    source_ip=src_ip,
                    hostname=matched[0].hostname,
                    evidence={
                        "registered_domain": reg_domain,
                        "indicators": sorted(indicators),
                        "matched_query_count": len(matched),
                        "unique_subdomain_count": len(unique_subdomains),
                        "sample_queries": [
                            str(e.get("dns.question.name", "")) for e in matched[:10]
                        ],
                        "query_types": qtypes,
                        "max_query_length": max_observed_len,
                        "max_subdomain_entropy": round(max_observed_entropy, 2),
                    },
                    event_ids=[e.event_id for e in matched],
                    first_seen=matched[0].timestamp,
                    last_seen=matched[-1].timestamp,
                )
            )

        return findings
