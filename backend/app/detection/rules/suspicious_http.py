"""SENT-WEB-001: Suspicious HTTP Activity."""

from __future__ import annotations

import re
from collections.abc import Sequence

from app.detection.base import Finding, MitreMapping, RuleConfig, RuleMetadata
from app.detection.utils import decode_url_multi, is_ip_allowlisted
from app.detection.windowing import group_events_by, maximal_window
from app.domain.enums import EventType, Severity
from app.domain.events import NormalizedEvent

DEFAULT_SCANNER_UAS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "gobuster",
    "dirbuster",
    "feroxbuster",
    "wpscan",
    "nuclei",
    "zgrab",
    "acunetix",
    "nessus",
]

# Bounded, non-backtracking patterns evaluated on length-capped decoded URLs.
_TRAVERSAL_RE = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/|\\windows\\win\.ini)",
    re.IGNORECASE,
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|/)(?:\.env|\.git/config|\.git/HEAD|wp-config\.php|\.aws/credentials|"
    r"phpinfo\.php|actuator/env|server-status|\.htpasswd)(?:$|[/?#])",
    re.IGNORECASE,
)
_SQLI_RE = re.compile(
    r"(?:union\s+(?:all\s+)?select|'\s*or\s+['1]\s*=\s*['1]|\"\s*or\s+[\"1]\s*=\s*[\"1]|"
    r"sleep\(\d+\)|benchmark\(\d+|information_schema\.|waitfor\s+delay)",
    re.IGNORECASE,
)
_XSS_RE = re.compile(
    r"(?:<\s*script\b|javascript\s*:|on(?:error|load|mouseover)\s*=)",
    re.IGNORECASE,
)


def _classify_http_event(ev: NormalizedEvent, scanner_tokens: tuple[str, ...]) -> list[str]:
    raw_url = str(ev.get("url.original") or ev.get("url.path") or "")
    query = str(ev.get("url.query") or "")
    combined = f"{raw_url}?{query}" if query and query not in raw_url else raw_url
    decoded = decode_url_multi(combined, max_passes=3, max_length=2048)

    matched: list[str] = []
    if _TRAVERSAL_RE.search(decoded):
        matched.append("directory_traversal")
    if _SENSITIVE_PATH_RE.search(decoded):
        matched.append("sensitive_file_probe")
    if _SQLI_RE.search(decoded):
        matched.append("sqli_attempt")
    if _XSS_RE.search(decoded):
        matched.append("xss_attempt")

    ua = str(ev.get("user_agent.original") or "").lower()
    if any(token in ua for token in scanner_tokens):
        matched.append("scanner_user_agent")

    return matched


class SuspiciousHttpRule:
    metadata = RuleMetadata(
        id="SENT-WEB-001",
        name="Suspicious HTTP Activity",
        description=(
            "Detects web attacks and reconnaissance against HTTP services: directory "
            "traversal (including double URL-encoded payloads), sensitive file probes "
            "(`.env`, `.git/config`), SQL injection and XSS patterns, known scanner "
            "user agents, and bursts of HTTP 404 responses (forced browsing)."
        ),
        category="web",
        default_severity=Severity.MEDIUM,
        default_threshold=30,
        default_time_window_seconds=300,
        default_parameters={
            "allowlist_ips": [],
            "scanner_user_agents": DEFAULT_SCANNER_UAS,
        },
        mitre_mappings=(
            MitreMapping(technique_id="T1190", is_primary=True),
            MitreMapping(technique_id="T1595.002", is_primary=False),
            MitreMapping(technique_id="T1595.003", is_primary=False),
        ),
        investigation_steps=(
            "Inspect the HTTP response status codes and response sizes: a 200 OK on a traversal or `.env` request indicates likely exposure.",
            "Review application logs and database queries around the event timestamps.",
            "Check whether the source IP performed port scanning prior to the HTTP probes.",
        ),
        remediation_steps=(
            "Block the attacking IP at the reverse proxy or WAF.",
            "Ensure `.env`, `.git` and backup files are never served by the web root.",
            "Validate and canonicalise file paths server-side and use parameterized queries.",
        ),
    )
    event_types = frozenset({EventType.HTTP_REQUEST})

    def evaluate(self, events: Sequence[NormalizedEvent], config: RuleConfig) -> list[Finding]:
        if not config.enabled:
            return []

        allowlist: list[str] = list(config.parameters.get("allowlist_ips", []))
        scanner_tokens = tuple(
            str(s).lower()
            for s in config.parameters.get("scanner_user_agents", DEFAULT_SCANNER_UAS)
            if str(s).strip()
        )

        http_events = [
            ev
            for ev in events
            if ev.event_type == EventType.HTTP_REQUEST
            and ev.source_ip
            and not is_ip_allowlisted(ev.source_ip, allowlist)
        ]
        by_ip = group_events_by(http_events, lambda ev: ev.source_ip)

        findings: list[Finding] = []
        for src_ip, ip_events in by_ip.items():
            indicator_events: list[NormalizedEvent] = []
            indicators: set[str] = set()
            high_risk_200 = False

            for ev in ip_events:
                ev_indicators = _classify_http_event(ev, scanner_tokens)
                if ev_indicators:
                    indicator_events.append(ev)
                    indicators.update(ev_indicators)
                    status = int(ev.get("http.response.status_code") or 0)
                    if (
                        status
                        and 200 <= status < 300
                        and any(
                            ind in ("directory_traversal", "sensitive_file_probe", "sqli_attempt")
                            for ind in ev_indicators
                        )
                    ):
                        high_risk_200 = True

            not_found_events = [
                ev for ev in ip_events if int(ev.get("http.response.status_code") or 0) == 404
            ]
            burst_404 = maximal_window(
                not_found_events,
                config.time_window_seconds,
                lambda win: len(win) >= config.threshold,
            )
            if burst_404:
                indicators.add("http_404_burst")

            if not indicators:
                continue

            combined_map = {ev.event_id: ev for ev in [*indicator_events, *(burst_404 or [])]}
            matched = sorted(combined_map.values(), key=lambda e: e.timestamp)

            severity = (
                Severity.HIGH
                if high_risk_200
                or any(
                    ind in indicators
                    for ind in ("directory_traversal", "sqli_attempt", "sensitive_file_probe")
                )
                else config.severity
            )
            if high_risk_200:
                severity = Severity.CRITICAL

            sampled_paths = [
                f"{e.get('http.request.method', 'GET')} {e.get('url.original', e.get('url.path', '/'))} "
                f"-> {e.get('http.response.status_code', '?')}"
                for e in matched[:12]
            ]
            user_agents = sorted(
                {str(e.get("user_agent.original")) for e in matched if e.get("user_agent.original")}
            )

            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    severity=severity,
                    group_key=f"src_ip={src_ip}",
                    title=(
                        f"Suspicious HTTP activity from {src_ip} ({', '.join(sorted(indicators))})"
                    ),
                    description=(
                        f"Source IP {src_ip} sent {len(matched)} suspicious HTTP request(s) "
                        f"matching indicators: {', '.join(sorted(indicators))}."
                        + (
                            " At least one exploit/probe request returned HTTP 2xx."
                            if high_risk_200
                            else ""
                        )
                    ),
                    mitre_technique_id=self.metadata.primary_technique_id,
                    source_ip=src_ip,
                    hostname=matched[0].hostname,
                    evidence={
                        "indicators": sorted(indicators),
                        "matched_request_count": len(matched),
                        "not_found_burst_count": len(burst_404) if burst_404 else 0,
                        "potential_successful_probe": high_risk_200,
                        "sampled_requests": sampled_paths,
                        "user_agents": user_agents[:10],
                    },
                    event_ids=[e.event_id for e in matched],
                    first_seen=matched[0].timestamp,
                    last_seen=matched[-1].timestamp,
                )
            )

        return findings
