"""Parser for Linux iptables / Netfilter / UFW kernel firewall logs.

Example line:
Nov 16 10:15:32 gw01 kernel: [4210.11] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.1.10 LEN=44 PROTO=TCP SPT=54321 DPT=22 SYN
"""

from __future__ import annotations

import re

from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import FieldValue, NormalizedEvent
from app.ingestion.parsers.base import (
    LogParser,
    ParseContext,
    ParseError,
    parse_syslog_header,
)

KV_PAIR_RE = re.compile(r"\b([A-Z]{2,10})=([^\s]+)")
TCP_FLAGS = ("SYN", "ACK", "FIN", "RST", "PSH", "URG")
ACTION_RE = re.compile(
    r"(?:\bUFW\s+|\bIPTABLES[_-]?|\bFW[_-]?)?(BLOCK|DROP|DENY|REJECT|ALLOW|ACCEPT|PASS)\b",
    re.IGNORECASE,
)


class IptablesParser(LogParser):
    name = "iptables"
    description = "Linux Netfilter / iptables / UFW firewall log"

    def matches(self, line: str) -> bool:
        return "SRC=" in line and "DST=" in line and "PROTO=" in line

    def parse(self, line: str, ctx: ParseContext) -> NormalizedEvent:
        record = parse_syslog_header(line, ctx)
        pairs = dict(KV_PAIR_RE.findall(record.message))
        src_ip = pairs.get("SRC")
        dst_ip = pairs.get("DST")
        proto = pairs.get("PROTO")
        if not src_ip or not dst_ip or not proto:
            raise ParseError("Firewall line missing SRC, DST or PROTO")

        action_match = ACTION_RE.search(record.message)
        raw_verb = action_match.group(1).upper() if action_match else "BLOCK"
        if raw_verb in ("ALLOW", "ACCEPT", "PASS"):
            action = "firewall_allow"
            outcome = EventOutcome.SUCCESS
            severity = Severity.INFORMATIONAL
        else:
            action = "firewall_block"
            outcome = EventOutcome.FAILURE
            severity = Severity.LOW

        spt = _optional_int(pairs.get("SPT"), "SPT")
        dpt = _optional_int(pairs.get("DPT"), "DPT")
        flags = [flag for flag in TCP_FLAGS if re.search(rf"\b{flag}\b", record.message)]

        fields: dict[str, FieldValue] = {
            "firewall.rule_action": raw_verb.lower(),
        }
        if "IN" in pairs:
            fields["network.interface.in"] = pairs["IN"][:32]
        if "OUT" in pairs:
            fields["network.interface.out"] = pairs["OUT"][:32]
        if flags:
            fields["network.tcp.flags"] = flags

        try:
            return NormalizedEvent(
                timestamp=record.timestamp,
                event_type=EventType.FIREWALL,
                event_action=action,
                event_outcome=outcome,
                severity=severity,
                log_source=self.name,
                raw_event=line,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=spt,
                destination_port=dpt,
                protocol=proto.lower()[:16],
                hostname=record.host,
                service="firewall",
                is_synthetic=ctx.is_synthetic,
                fields=fields,
            )
        except ValueError as exc:
            raise ParseError(f"Invalid field in firewall log: {exc}") from exc


def _optional_int(raw: str | None, label: str) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise ParseError(f"Invalid integer for {label}") from exc
