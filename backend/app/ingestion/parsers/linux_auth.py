"""Parser for Linux authentication logs (/var/log/auth.log, /var/log/secure).

Supported messages: sshd logins (password/publickey, failures, invalid users),
sudo command execution and failures, su, PAM authentication failures and local
account creation (useradd).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import ClassVar

from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import FieldValue, NormalizedEvent
from app.ingestion.parsers.base import (
    IgnoredLine,
    LogParser,
    ParseContext,
    ParseError,
    SyslogRecord,
    parse_syslog_header,
)

_IP = r"(?P<ip>[0-9a-fA-F.:]{2,45})"
_USER = r"(?P<user>[^\s]{1,256})"

SSH_FAILED = re.compile(
    rf"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for "
    rf"(?P<invalid>invalid user )?{_USER} from {_IP} port (?P<port>\d{{1,5}})"
)
SSH_ACCEPTED = re.compile(
    rf"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|gssapi-with-mic) for "
    rf"{_USER} from {_IP} port (?P<port>\d{{1,5}})"
)
SSH_INVALID_USER = re.compile(
    rf"^Invalid user (?P<user>\S*) from {_IP}(?: port (?P<port>\d{{1,5}}))?"
)
SUDO_COMMAND = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<reason>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>[^;]*) ; "
    r"USER=(?P<target>\S+) ;(?: [A-Z]+=[^;]* ;)* COMMAND=(?P<command>.*)$"
)
SU_SESSION = re.compile(
    r"^(?P<failed>FAILED SU )?\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)"
)
PAM_AUTH_FAILURE = re.compile(
    r"^pam_unix\((?P<service>[\w-]+):auth\): authentication failure;.*?"
    r"(?:rhost=(?P<rhost>\S*))?\s*(?:user=(?P<user>\S+))?\s*$"
)
PAM_SESSION = re.compile(
    r"^pam_unix\((?P<service>[\w-]+):session\): session (?P<state>opened|closed) for user "
    r"(?P<user>[^\s(]+)"
)
USERADD = re.compile(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)")


class LinuxAuthParser(LogParser):
    name = "linux_auth"
    description = "Linux auth.log / secure (sshd, sudo, su, PAM, useradd)"

    _PROGRAMS = ("sshd", "sudo", "su", "useradd", "login", "systemd-logind")

    def matches(self, line: str) -> bool:
        return any(f" {p}[" in line or f" {p}:" in line for p in self._PROGRAMS)

    def parse(self, line: str, ctx: ParseContext) -> NormalizedEvent:
        record = parse_syslog_header(line, ctx)
        handler = self._HANDLERS.get(record.program)
        if handler is None:
            raise IgnoredLine(f"Program not monitored: {record.program[:32]}")
        event = handler(self, record, line, ctx)
        if event is None:
            raise IgnoredLine(f"{record.program} message not security-relevant")
        return event

    # ------------------------------------------------------------------ helpers
    def _base(
        self,
        record: SyslogRecord,
        line: str,
        ctx: ParseContext,
        *,
        event_type: EventType,
        event_action: str,
        event_outcome: EventOutcome,
        severity: Severity = Severity.INFORMATIONAL,
        source_ip: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        protocol: str | None = None,
        username: str | None = None,
        fields: dict[str, FieldValue] | None = None,
    ) -> NormalizedEvent:
        all_fields: dict[str, FieldValue] = dict(fields or {})
        if record.pid is not None:
            all_fields["process.pid"] = record.pid
        try:
            return NormalizedEvent(
                timestamp=record.timestamp,
                event_type=event_type,
                event_action=event_action,
                event_outcome=event_outcome,
                severity=severity,
                log_source=self.name,
                raw_event=line,
                source_ip=source_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
                username=username,
                hostname=record.host,
                service=record.program,
                is_synthetic=ctx.is_synthetic,
                fields=all_fields,
            )
        except ValueError as exc:  # invalid IP or port in the log line
            raise ParseError(f"Invalid field value: {exc}") from exc

    # ------------------------------------------------------------------ sshd
    def _sshd(self, r: SyslogRecord, line: str, ctx: ParseContext) -> NormalizedEvent | None:
        if m := SSH_FAILED.match(r.message):
            return self._base(
                r,
                line,
                ctx,
                event_type=EventType.AUTHENTICATION,
                event_action="ssh_login",
                event_outcome=EventOutcome.FAILURE,
                severity=Severity.LOW,
                source_ip=m["ip"],
                source_port=int(m["port"]),
                destination_port=22,
                protocol="ssh",
                username=m["user"],
                fields={"auth.method": m["method"], "user.invalid": bool(m["invalid"])},
            )
        if m := SSH_ACCEPTED.match(r.message):
            return self._base(
                r,
                line,
                ctx,
                event_type=EventType.AUTHENTICATION,
                event_action="ssh_login",
                event_outcome=EventOutcome.SUCCESS,
                severity=Severity.INFORMATIONAL,
                source_ip=m["ip"],
                source_port=int(m["port"]),
                destination_port=22,
                protocol="ssh",
                username=m["user"],
                fields={"auth.method": m["method"]},
            )
        if m := SSH_INVALID_USER.match(r.message):
            # sshd logs "Invalid user" *and* "Failed password for invalid user" for
            # the same attempt. A distinct action prevents double counting.
            return self._base(
                r,
                line,
                ctx,
                event_type=EventType.AUTHENTICATION,
                event_action="ssh_invalid_user",
                event_outcome=EventOutcome.FAILURE,
                severity=Severity.LOW,
                source_ip=m["ip"],
                source_port=int(m["port"]) if m["port"] else None,
                destination_port=22,
                protocol="ssh",
                username=m["user"] or None,
            )
        if m := PAM_SESSION.match(r.message):
            return self._pam_session(r, line, ctx, m)
        if PAM_AUTH_FAILURE.match(r.message):
            # Duplicated by the "Failed password" line that sshd logs next.
            raise IgnoredLine("PAM failure duplicated by sshd 'Failed password' line")
        raise IgnoredLine("sshd message not security-relevant for this platform")

    # ------------------------------------------------------------------ sudo
    def _sudo(self, r: SyslogRecord, line: str, ctx: ParseContext) -> NormalizedEvent | None:
        if m := SUDO_COMMAND.match(r.message):
            reason = (m["reason"] or "").strip()
            failed = bool(reason)
            return self._base(
                r,
                line,
                ctx,
                event_type=EventType.PROCESS_EXECUTION,
                event_action="sudo",
                event_outcome=EventOutcome.FAILURE if failed else EventOutcome.SUCCESS,
                severity=Severity.MEDIUM if failed else Severity.LOW,
                username=m["user"],
                fields={
                    "process.command_line": m["command"][:2048],
                    "process.working_directory": m["pwd"][:512],
                    "user.target.name": m["target"],
                    "process.tty": m["tty"],
                    **({"event.reason": reason[:256]} if failed else {}),
                },
            )
        if m := PAM_AUTH_FAILURE.match(r.message):
            return self._base(
                r,
                line,
                ctx,
                event_type=EventType.AUTHENTICATION,
                event_action="sudo_auth",
                event_outcome=EventOutcome.FAILURE,
                severity=Severity.LOW,
                username=m["user"],
            )
        if m := PAM_SESSION.match(r.message):
            return self._pam_session(r, line, ctx, m)
        return None

    # ------------------------------------------------------------------ su
    def _su(self, r: SyslogRecord, line: str, ctx: ParseContext) -> NormalizedEvent | None:
        if m := SU_SESSION.match(r.message):
            failed = bool(m["failed"])
            return self._base(
                r,
                line,
                ctx,
                event_type=EventType.AUTHENTICATION,
                event_action="su",
                event_outcome=EventOutcome.FAILURE if failed else EventOutcome.SUCCESS,
                severity=Severity.MEDIUM if failed else Severity.LOW,
                username=m["user"],
                fields={"user.target.name": m["target"], "process.tty": m["tty"]},
            )
        if m := PAM_AUTH_FAILURE.match(r.message):
            return self._base(
                r,
                line,
                ctx,
                event_type=EventType.AUTHENTICATION,
                event_action="su",
                event_outcome=EventOutcome.FAILURE,
                severity=Severity.MEDIUM,
                username=m["user"],
            )
        if m := PAM_SESSION.match(r.message):
            return self._pam_session(r, line, ctx, m)
        return None

    # ------------------------------------------------------------------ useradd
    def _useradd(self, r: SyslogRecord, line: str, ctx: ParseContext) -> NormalizedEvent | None:
        if m := USERADD.match(r.message):
            return self._base(
                r,
                line,
                ctx,
                event_type=EventType.PROCESS_EXECUTION,
                event_action="user_add",
                event_outcome=EventOutcome.SUCCESS,
                severity=Severity.MEDIUM,
                username=None,
                fields={"user.target.name": m["user"].strip()[:256], "user.target.id": m["uid"]},
            )
        return None

    def _pam_session(
        self, r: SyslogRecord, line: str, ctx: ParseContext, m: re.Match[str]
    ) -> NormalizedEvent:
        return self._base(
            r,
            line,
            ctx,
            event_type=EventType.AUTHENTICATION,
            event_action=f"session_{m['state']}",
            event_outcome=EventOutcome.SUCCESS,
            username=m["user"],
            fields={"pam.service": m["service"]},
        )

    _HANDLERS: ClassVar[
        dict[
            str,
            Callable[[LinuxAuthParser, SyslogRecord, str, ParseContext], NormalizedEvent | None],
        ]
    ] = {
        "sshd": _sshd,
        "sudo": _sudo,
        "su": _su,
        "useradd": _useradd,
    }
