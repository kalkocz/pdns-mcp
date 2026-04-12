"""Core data models for pdns-mcp."""

from __future__ import annotations

import time
import secrets
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# DNS record structures
# ---------------------------------------------------------------------------

@dataclass
class Record:
    content: str
    disabled: bool = False


@dataclass
class RRSet:
    name: str       # canonical, trailing dot
    type: str       # uppercase: A, AAAA, MX, etc.
    ttl: int
    records: list[Record]
    comments: list[dict] = field(default_factory=list)

    @classmethod
    def from_pdns(cls, data: dict) -> "RRSet":
        return cls(
            name=data["name"],
            type=data["type"],
            ttl=data.get("ttl", 300),
            records=[Record(r["content"], r.get("disabled", False))
                     for r in data.get("records", [])],
            comments=data.get("comments", []),
        )

    def to_pdns_patch(self, changetype: str = "REPLACE") -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "ttl": self.ttl,
            "changetype": changetype,
            "records": [{"content": r.content, "disabled": r.disabled}
                        for r in self.records],
        }


@dataclass
class Zone:
    id: str
    name: str       # canonical, trailing dot
    kind: str       # Native | Master | Slave
    serial: int
    dnssec: bool
    rrsets: list[RRSet] = field(default_factory=list)

    @classmethod
    def from_pdns(cls, data: dict) -> "Zone":
        return cls(
            id=data["id"],
            name=data["name"],
            kind=data.get("kind", "Native"),
            serial=data.get("serial", 0),
            dnssec=data.get("dnssec", False),
            rrsets=[RRSet.from_pdns(r) for r in data.get("rrsets", [])],
        )


# ---------------------------------------------------------------------------
# Pending change (preview → commit)
# ---------------------------------------------------------------------------

@dataclass
class PendingChange:
    token: str
    operation: str          # SET | DELETE | CREATE_ZONE | DELETE_ZONE | SET_CATALOG | FLUSH_CACHE | NOTIFY
    zone: str
    name: str | None
    record_type: str | None
    pdns_payload: dict      # pre-built body for the PDNS API call
    pdns_method: str        # PATCH | POST | DELETE | PUT
    pdns_url_path: str      # relative path, e.g. /zones/example.com./
    zone_serial: int | None = None  # serial at preview time; re-checked at commit
    created_at: float = field(default_factory=time.monotonic)
    used: bool = False
    used_at: float | None = None

    @staticmethod
    def new_token() -> str:
        # 144 bits of entropy — sufficient for a short-lived write capability token
        return "tok_" + secrets.token_urlsafe(18)

    @staticmethod
    def fingerprint(token: str) -> str:
        """Return a short non-reversible token fingerprint safe to log/audit."""
        import hashlib
        return "fp_" + hashlib.sha256(token.encode()).hexdigest()[:12]

    def is_expired(self, ttl_seconds: int = 60) -> bool:
        return (time.monotonic() - self.created_at) > ttl_seconds

    def consume(self) -> None:
        self.used = True
        self.used_at = time.monotonic()


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    passed: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def fail(self, msg: str) -> "ValidationResult":
        self.passed = False
        self.errors.append(msg)
        return self

    def warn(self, msg: str) -> "ValidationResult":
        self.warnings.append(msg)
        return self


# ---------------------------------------------------------------------------
# Diff output (what preview tools return to Claude)
# ---------------------------------------------------------------------------

@dataclass
class Diff:
    zone: str
    name: str | None
    record_type: str | None
    action: str             # CREATE | REPLACE | DELETE | CREATE_ZONE | DELETE_ZONE | FLUSH_CACHE | NOTIFY
    current: dict | None    # None if record didn't exist
    proposed: dict | None   # None if deleting


@dataclass
class PreviewResult:
    diff: Diff
    validation: ValidationResult
    confirmation_token: str
    expires_in_seconds: int = 60

    def to_dict(self) -> dict[str, Any]:
        return {
            "diff": {
                "zone": self.diff.zone,
                "name": self.diff.name,
                "type": self.diff.record_type,
                "action": self.diff.action,
                "current": self.diff.current,
                "proposed": self.diff.proposed,
            },
            "validation": {
                "passed": self.validation.passed,
                "errors": self.validation.errors,
                "warnings": self.validation.warnings,
            },
            "confirmation_token": self.confirmation_token,
            "expires_in_seconds": self.expires_in_seconds,
        }
