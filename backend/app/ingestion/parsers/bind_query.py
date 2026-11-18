"""Parser for BIND 9 DNS query logs (standalone or syslog-wrapped).

Supported formats:
* Syslog-wrapped:
  Nov 16 10:15:32 ns01 named[912]: client @0x7f10 10.0.1.25#53214 (api.example.test): query: api.example.test IN A + (10.0.1.2)
* Standalone BIND timestamp:
  16-Nov-2026 10:15:32.123 client @0x7f10 10.0.1.25#53214 (api.example.test): query: api.example.test IN A +E(0) (10.0.1.2)
"""

from __future__ import annotations

import re
from datetime import datetime

from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import FieldValue, NormalizedEvent
from app.ingestion.parsers.base import (
    MONTHS,
    LogParser,
    ParseContext,
    ParseError,
    parse_syslog_header,
)

BIND_STANDALONE_TS_RE = re.compile(
    r"^(?P<day>\d{2})-(?P<mon>[A-Z][a-z]{2})-(?P<year>\d{4})\s+"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.(?P<ms>\d{1,3}))?\s+"
    r"(?P<rest>.*)$"
)

BIND_QUERY_BODY_RE = re.compile(
    r"^(?:queries:\s+info:\s+)?"
    r"client\s+(?:@\S+\s+)?(?P<src_ip>[0-9a-fA-F.:]{2,45})#(?P<src_port>\d{1,5})"
    r"(?:\s+\([^)]*\))?:\s+"
    r"(?:view\s+\S+:\s+)?"
    r"query:\s+(?P<qname>\S+)\s+(?P<qclass>[A-Z0-9]+)\s+(?P<qtype>[A-Z0-9]+)"
    r"(?:\s+(?P<flags>[+-]\S*))?"
    r"(?:\s+\((?P<server_ip>[0-9a-fA-F.:]{2,45})\))?\s*$"
)


class BindQueryParser(LogParser):
    name = "bind_query"
    description = "BIND 9 DNS query log"

    def matches(self, line: str) -> bool:
        return "client " in line and "query:" in line

    def parse(self, line: str, ctx: ParseContext) -> NormalizedEvent:
        hostname: str | None = None
        if m_ts := BIND_STANDALONE_TS_RE.match(line):
            try:
                timestamp = datetime(
                    int(m_ts["year"]),
                    MONTHS[m_ts["mon"]],
                    int(m_ts["day"]),
                    int(m_ts["h"]),
                    int(m_ts["m"]),
                    int(m_ts["s"]),
                    int((m_ts["ms"] or "0").ljust(3, "0")) * 1000,
                    tzinfo=ctx.default_timezone,
                )
            except (KeyError, ValueError) as exc:
                raise ParseError("Invalid BIND timestamp") from exc
            body = m_ts["rest"]
        else:
            record = parse_syslog_header(line, ctx)
            timestamp = record.timestamp
            hostname = record.host
            body = record.message

        m = BIND_QUERY_BODY_RE.match(body)
        if not m:
            raise ParseError("Line does not match BIND query log format")

        qname = m["qname"].rstrip(".")
        if not qname or len(qname) > 255:
            raise ParseError("Invalid DNS query name")

        qtype = m["qtype"].upper()[:16]
        qclass = m["qclass"].upper()[:16]

        fields: dict[str, FieldValue] = {
            "dns.question.name": qname,
            "dns.question.type": qtype,
            "dns.question.class": qclass,
            "dns.question.length": len(qname),
        }
        if m["flags"]:
            fields["dns.flags"] = m["flags"][:16]

        try:
            return NormalizedEvent(
                timestamp=timestamp,
                event_type=EventType.DNS_QUERY,
                event_action="dns_query",
                event_outcome=EventOutcome.SUCCESS,
                severity=Severity.INFORMATIONAL,
                log_source=self.name,
                raw_event=line,
                source_ip=m["src_ip"],
                source_port=int(m["src_port"]),
                destination_ip=m["server_ip"],
                destination_port=53,
                protocol="udp",
                hostname=hostname,
                service="named",
                is_synthetic=ctx.is_synthetic,
                fields=fields,
            )
        except ValueError as exc:
            raise ParseError(f"Invalid field in DNS log: {exc}") from exc
