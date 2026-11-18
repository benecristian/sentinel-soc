"""Shared, framework-independent domain enumerations.

These enums are the single source of truth for categorical values. The database
stores them as VARCHAR columns guarded by CHECK constraints generated from the
same enums, so the API, the ORM and the database can never disagree.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank for comparisons (informational=0 ... critical=4)."""
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class EventType(StrEnum):
    """Coarse event category, loosely modelled on ECS `event.category`."""

    AUTHENTICATION = "authentication"
    NETWORK_CONNECTION = "network_connection"
    FIREWALL = "firewall"
    DNS_QUERY = "dns_query"
    HTTP_REQUEST = "http_request"
    PROCESS_EXECUTION = "process_execution"


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class UserRole(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"

    @property
    def level(self) -> int:
        return {UserRole.VIEWER: 0, UserRole.ANALYST: 1, UserRole.ADMIN: 2}[self]


class AlertStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


OPEN_ALERT_STATUSES: frozenset[AlertStatus] = frozenset(
    {AlertStatus.NEW, AlertStatus.INVESTIGATING}
)


class IncidentStatus(StrEnum):
    """Lifecycle inspired by the NIST SP 800-61 incident handling phases."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED = "closed"


class TimelineEntryType(StrEnum):
    CREATED = "created"
    STATUS_CHANGE = "status_change"
    ALERT_ADDED = "alert_added"
    ALERT_REMOVED = "alert_removed"
    NOTE = "note"
    ACTION = "action"
    UPDATE = "update"


class IngestionSourceKind(StrEnum):
    UPLOAD = "upload"
    API = "api"
    SIMULATION = "simulation"


class SimulationStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
