"""Unit tests for all 5 log parsers, format auto-detection and normalization."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.domain.enums import EventOutcome, EventType
from app.ingestion.parsers import (
    BindQueryParser,
    IgnoredLine,
    IptablesParser,
    JsonEventsParser,
    LinuxAuthParser,
    ParseContext,
    ParseError,
    WebAccessParser,
    detect_parser,
)


def test_linux_auth_parser_ssh_sudo_useradd_and_year_rollover() -> None:
    parser = LinuxAuthParser()
    # Reference time is Jan 1 2027; a Dec 31 log line must roll back to 2026.
    ctx = ParseContext(reference_time=datetime(2027, 1, 1, 1, 0, 0, tzinfo=UTC))

    fail_line = (
        "Dec 31 23:55:10 bastion-01 sshd[1920]: "
        "Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2"
    )
    ev = parser.parse(fail_line, ctx)
    assert ev.timestamp.year == 2026
    assert ev.event_type == EventType.AUTHENTICATION
    assert ev.event_action == "ssh_login"
    assert ev.event_outcome == EventOutcome.FAILURE
    assert ev.source_ip == "203.0.113.5"
    assert ev.username == "admin"
    assert ev.get("user.invalid") is True

    sudo_line = (
        "Nov 16 10:00:00 srv01 sudo: intern : user NOT in sudoers ; "
        "TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    )
    sudo_ev = parser.parse(
        sudo_line, ParseContext(reference_time=datetime(2026, 11, 16, 12, tzinfo=UTC))
    )
    assert sudo_ev.event_type == EventType.PROCESS_EXECUTION
    assert sudo_ev.event_action == "sudo"
    assert sudo_ev.event_outcome == EventOutcome.FAILURE
    assert sudo_ev.get("process.command_line") == "/bin/cat /etc/shadow"

    # Non-security-relevant cron/sshd noise raises IgnoredLine, not ParseError
    with pytest.raises(IgnoredLine):
        parser.parse("Nov 16 10:00:00 srv01 CRON[99]: (root) CMD (run-parts /etc/cron.hourly)", ctx)


def test_web_access_parser() -> None:
    parser = WebAccessParser()
    line = (
        "198.51.100.42 - alice [16/Nov/2026:10:15:32 +0000] "
        '"GET /admin/config?debug=1 HTTP/1.1" 403 512 "https://example.test/" "Nikto/2.5"'
    )
    ev = parser.parse(line, ParseContext())
    assert ev.event_type == EventType.HTTP_REQUEST
    assert ev.event_outcome == EventOutcome.FAILURE
    assert ev.source_ip == "198.51.100.42"
    assert ev.username == "alice"
    assert ev.get("url.path") == "/admin/config"
    assert ev.get("url.query") == "debug=1"
    assert ev.get("http.response.status_code") == 403
    assert ev.get("user_agent.original") == "Nikto/2.5"

    with pytest.raises(ParseError):
        parser.parse("not a web log line", ParseContext())


def test_iptables_parser() -> None:
    parser = IptablesParser()
    line = (
        "Nov 16 10:15:32 fw01 kernel: [4210.1] [UFW BLOCK] IN=eth0 OUT= "
        "SRC=203.0.113.50 DST=10.0.1.10 LEN=44 PROTO=TCP SPT=54321 DPT=22 SYN"
    )
    ev = parser.parse(line, ParseContext(reference_time=datetime(2026, 11, 16, 12, tzinfo=UTC)))
    assert ev.event_type == EventType.FIREWALL
    assert ev.event_action == "firewall_block"
    assert ev.event_outcome == EventOutcome.FAILURE
    assert ev.source_ip == "203.0.113.50"
    assert ev.destination_ip == "10.0.1.10"
    assert ev.destination_port == 22
    assert ev.protocol == "tcp"


def test_bind_query_parser_both_formats() -> None:
    parser = BindQueryParser()
    syslog_line = (
        "Nov 16 10:15:32 ns01 named[912]: client @0x7f10 10.0.1.25#53214 "
        "(sub.example.test): query: sub.example.test IN TXT + (10.0.1.2)"
    )
    ev1 = parser.parse(
        syslog_line, ParseContext(reference_time=datetime(2026, 11, 16, 12, tzinfo=UTC))
    )
    assert ev1.event_type == EventType.DNS_QUERY
    assert ev1.source_ip == "10.0.1.25"
    assert ev1.get("dns.question.name") == "sub.example.test"
    assert ev1.get("dns.question.type") == "TXT"

    standalone_line = (
        "16-Nov-2026 10:15:32.123 client 10.0.1.25#53214 (example.test): "
        "query: example.test IN A + (10.0.1.2)"
    )
    ev2 = parser.parse(standalone_line, ParseContext())
    assert ev2.timestamp.year == 2026
    assert ev2.get("dns.question.name") == "example.test"


def test_json_parser_and_auto_detection() -> None:
    json_line = (
        '{"timestamp":"2026-11-16T10:15:32Z","event_type":"network_connection",'
        '"event_outcome":"success","source_ip":"10.0.1.5","destination_ip":"10.0.1.10",'
        '"destination_port":443,"protocol":"tcp"}'
    )
    detected = detect_parser([json_line])
    assert isinstance(detected, JsonEventsParser)
    ev = detected.parse(json_line, ParseContext())
    assert ev.event_type == EventType.NETWORK_CONNECTION
    assert ev.destination_port == 443

    with pytest.raises(ParseError):
        detected.parse(
            '{"timestamp":"2026-11-16T10:15:32Z","event_type":"authentication","source_ip":"999.999.999.999"}',
            ParseContext(),
        )
