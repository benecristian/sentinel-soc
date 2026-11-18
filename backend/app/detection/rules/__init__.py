"""Registry of all built-in detection rules."""

from __future__ import annotations

from app.detection.base import DetectionRuleContract
from app.detection.rules.multiple_failed_logins import MultipleFailedLoginsRule
from app.detection.rules.password_spraying import PasswordSprayingRule
from app.detection.rules.port_scanning import PortScanningRule
from app.detection.rules.privileged_activity import PrivilegedActivityRule
from app.detection.rules.ssh_brute_force import SshBruteForceRule
from app.detection.rules.suspicious_dns import SuspiciousDnsRule
from app.detection.rules.suspicious_http import SuspiciousHttpRule

ALL_RULES: tuple[DetectionRuleContract, ...] = (
    SshBruteForceRule(),
    PasswordSprayingRule(),
    MultipleFailedLoginsRule(),
    PortScanningRule(),
    SuspiciousDnsRule(),
    SuspiciousHttpRule(),
    PrivilegedActivityRule(),
)

RULES_BY_ID: dict[str, DetectionRuleContract] = {rule.metadata.id: rule for rule in ALL_RULES}

__all__ = [
    "ALL_RULES",
    "RULES_BY_ID",
    "MultipleFailedLoginsRule",
    "PasswordSprayingRule",
    "PortScanningRule",
    "PrivilegedActivityRule",
    "SshBruteForceRule",
    "SuspiciousDnsRule",
    "SuspiciousHttpRule",
]
