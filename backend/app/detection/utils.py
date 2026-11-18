"""Pure helper functions for detection rules (allowlists, entropy, URL decoding, domains)."""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from collections.abc import Iterable
from urllib.parse import unquote

import tldextract

# Offline Public Suffix List extractor: `suffix_list_urls=()` guarantees that
# tldextract NEVER makes a network request at runtime.
_OFFLINE_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def is_ip_allowlisted(ip_str: str | None, allowlist: Iterable[str]) -> bool:
    """Return True if `ip_str` falls in any IP or CIDR entry in `allowlist`."""
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for raw_entry in allowlist:
        entry = str(raw_entry).strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy in bits per character (0.0 for empty strings)."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def decode_url_multi(value: str, max_passes: int = 3, max_length: int = 4096) -> str:
    """Iteratively percent-decode up to `max_passes` times to uncover double-encoding."""
    current = value[:max_length]
    for _ in range(max_passes):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded[:max_length]
    return current


def split_domain(qname: str) -> tuple[str, str, str]:
    """Return `(subdomain, registered_domain, suffix)` in lower case using offline PSL.

    Fallback for single-label or reserved `.test` / `.example` / `.invalid` /
    `.localhost` names (which are not in the Public Suffix List): treats the last
    two labels as the registered domain.
    """
    cleaned = qname.strip().rstrip(".").lower()
    if not cleaned:
        return "", "", ""
    ext = _OFFLINE_TLD_EXTRACTOR(cleaned)
    if ext.domain and ext.suffix:
        return ext.subdomain, f"{ext.domain}.{ext.suffix}", ext.suffix

    labels = cleaned.split(".")
    if len(labels) >= 2:
        registered = ".".join(labels[-2:])
        subdomain = ".".join(labels[:-2])
        return subdomain, registered, labels[-1]
    return "", cleaned, ""


def is_domain_allowlisted(qname: str, allowlist: Iterable[str]) -> bool:
    cleaned = qname.strip().rstrip(".").lower()
    if not cleaned:
        return False
    for entry in allowlist:
        dom = str(entry).strip().rstrip(".").lower()
        if not dom:
            continue
        if cleaned == dom or cleaned.endswith(f".{dom}"):
            return True
    return False
