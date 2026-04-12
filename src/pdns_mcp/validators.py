"""Per-type DNS record content validators.

Each validator receives the list of content strings for an rrset
and returns a ValidationResult. Validators do not call PDNS.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Callable

from .models import ValidationResult

# Type alias
Validator = Callable[[list[str], int], ValidationResult]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok() -> ValidationResult:
    return ValidationResult(passed=True)


def _ensure_trailing_dot(name: str) -> str:
    return name if name.endswith(".") else name + "."


def _is_valid_hostname(name: str) -> bool:
    """Check that a DNS name is syntactically valid (trailing dot OK)."""
    n = name.rstrip(".")
    if not n:
        return False
    if len(n) > 253:
        return False
    labels = n.split(".")
    label_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    return all(label_re.match(lbl) for lbl in labels)


# ---------------------------------------------------------------------------
# Per-type validators
# ---------------------------------------------------------------------------

def validate_A(records: list[str], ttl: int) -> ValidationResult:
    result = _ok()
    if not records:
        return result.fail("A record requires at least one content value")
    for r in records:
        try:
            addr = ipaddress.IPv4Address(r)
            if addr.packed == b"\x00\x00\x00\x00":
                result.warn(f"0.0.0.0 is unusual for an A record: {r}")
            if addr.is_multicast:
                result.fail(f"Multicast address not valid for A record: {r}")
        except ValueError:
            result.fail(f"Invalid IPv4 address: {r!r}")
    if ttl < 300:
        result.warn(f"TTL {ttl}s is low for an A record; consider 300+")
    return result


def validate_AAAA(records: list[str], ttl: int) -> ValidationResult:
    result = _ok()
    if not records:
        return result.fail("AAAA record requires at least one content value")
    for r in records:
        try:
            ipaddress.IPv6Address(r)
        except ValueError:
            result.fail(f"Invalid IPv6 address: {r!r}")
    return result


def validate_CNAME(records: list[str], ttl: int) -> ValidationResult:
    result = _ok()
    if len(records) != 1:
        return result.fail(
            f"CNAME must have exactly one record, got {len(records)}"
        )
    target = records[0]
    if not target.endswith("."):
        result.warn(
            f"CNAME target {target!r} does not end with '.'; "
            "PDNS will append the zone origin — confirm this is intended"
        )
    return result


def validate_MX(records: list[str], ttl: int) -> ValidationResult:
    result = _ok()
    if not records:
        return result.fail("MX record requires at least one content value")
    for r in records:
        parts = r.split(None, 1)
        if len(parts) != 2:
            result.fail(
                f"MX record must be '<priority> <hostname.>', got: {r!r}"
            )
            continue
        prio_str, host = parts
        try:
            prio = int(prio_str)
            if not (0 <= prio <= 65535):
                result.fail(f"MX priority {prio} out of range 0–65535")
        except ValueError:
            result.fail(f"MX priority must be an integer, got: {prio_str!r}")
        if not host.endswith("."):
            result.warn(
                f"MX hostname {host!r} does not end with '.'; "
                "PDNS will append the zone origin"
            )
    return result


def validate_NS(records: list[str], ttl: int) -> ValidationResult:
    result = _ok()
    if not records:
        return result.fail("NS record requires at least one value")
    for r in records:
        if not r.endswith("."):
            result.warn(f"NS value {r!r} does not end with '.'")
    return result


def validate_TXT(records: list[str], ttl: int) -> ValidationResult:
    result = _ok()
    if not records:
        return result.fail("TXT record requires at least one content value")
    for r in records:
        # PDNS stores TXT with surrounding quotes; content already stripped
        raw = r.strip('"')
        if len(raw.encode()) > 255:
            result.warn(
                f"TXT string is {len(raw.encode())} bytes (>255); "
                "PDNS will split into multiple strings automatically"
            )
    return result


def validate_PTR(records: list[str], ttl: int) -> ValidationResult:
    result = _ok()
    if len(records) != 1:
        return result.fail("PTR must have exactly one record")
    if not records[0].endswith("."):
        result.warn(f"PTR target {records[0]!r} does not end with '.'")
    return result


def validate_SRV(records: list[str], ttl: int) -> ValidationResult:
    result = _ok()
    if not records:
        return result.fail("SRV record requires at least one content value")
    for r in records:
        parts = r.split()
        if len(parts) != 4:
            result.fail(
                f"SRV record must be '<priority> <weight> <port> <target.>', "
                f"got: {r!r}"
            )
            continue
        prio_s, weight_s, port_s, target = parts
        for label, val_s in [("priority", prio_s), ("weight", weight_s)]:
            try:
                v = int(val_s)
                if not (0 <= v <= 65535):
                    result.fail(f"SRV {label} {v} out of range 0–65535")
            except ValueError:
                result.fail(f"SRV {label} must be an integer, got: {val_s!r}")
        try:
            port = int(port_s)
            if not (1 <= port <= 65535):
                result.fail(f"SRV port {port} out of range 1–65535")
        except ValueError:
            result.fail(f"SRV port must be an integer, got: {port_s!r}")
        if not target.endswith("."):
            result.warn(f"SRV target {target!r} does not end with '.'")
    return result


def validate_CAA(records: list[str], ttl: int) -> ValidationResult:
    result = _ok()
    valid_tags = {"issue", "issuewild", "iodef"}
    if not records:
        return result.fail("CAA record requires at least one content value")
    for r in records:
        # Expected: <flags> <tag> "<value>"
        m = re.match(r'^(\d+)\s+(\S+)\s+"([^"]*)"$', r)
        if not m:
            result.fail(
                f"CAA record must be '<flags> <tag> \"<value>\"', got: {r!r}"
            )
            continue
        flags_s, tag, _ = m.groups()
        try:
            flags = int(flags_s)
            if not (0 <= flags <= 255):
                result.fail(f"CAA flags {flags} out of range 0–255")
        except ValueError:
            result.fail(f"CAA flags must be an integer, got: {flags_s!r}")
        if tag.lower() not in valid_tags:
            result.warn(
                f"CAA tag {tag!r} is not one of the standard tags "
                f"{sorted(valid_tags)}"
            )
    return result


def validate_SOA(records: list[str], ttl: int) -> ValidationResult:
    result = ValidationResult(passed=False)
    result.fail(
        "Direct SOA edits are not supported. "
        "Use PowerDNS SOA-EDIT settings (soa_edit / soa_edit_api) instead."
    )
    return result


# ---------------------------------------------------------------------------
# TTL validation (type-agnostic, applied in addition to type validators)
# ---------------------------------------------------------------------------

def validate_ttl(ttl: int, min_ttl: int = 60, max_ttl: int = 86400) -> ValidationResult:
    result = _ok()
    if not isinstance(ttl, int):
        return result.fail(f"TTL must be an integer, got: {type(ttl).__name__}")
    if ttl < min_ttl:
        result.fail(f"TTL {ttl} is below minimum {min_ttl}")
    if ttl > max_ttl:
        result.fail(f"TTL {ttl} exceeds maximum {max_ttl}")
    return result


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

VALIDATORS: dict[str, Validator] = {
    "A":    validate_A,
    "AAAA": validate_AAAA,
    "CNAME": validate_CNAME,
    "MX":   validate_MX,
    "NS":   validate_NS,
    "TXT":  validate_TXT,
    "PTR":  validate_PTR,
    "SRV":  validate_SRV,
    "CAA":  validate_CAA,
    "SOA":  validate_SOA,
}


def validate_record(
    record_type: str,
    records: list[str],
    ttl: int,
    min_ttl: int = 60,
    max_ttl: int = 86400,
) -> ValidationResult:
    """
    Run TTL validation and per-type content validation.
    Returns the merged ValidationResult.
    """
    ttl_result = validate_ttl(ttl, min_ttl, max_ttl)

    type_upper = record_type.upper()
    validator = VALIDATORS.get(type_upper)
    if validator is None:
        # Unknown type — warn but don't block; PDNS will validate content
        type_result = ValidationResult(passed=True)
        type_result.warn(
            f"No content validator for type {type_upper!r}; "
            "relying on PowerDNS for content validation"
        )
    else:
        type_result = validator(records, ttl)

    # Merge: passed only if both pass
    combined = ValidationResult(
        passed=ttl_result.passed and type_result.passed,
        errors=ttl_result.errors + type_result.errors,
        warnings=ttl_result.warnings + type_result.warnings,
    )
    return combined
