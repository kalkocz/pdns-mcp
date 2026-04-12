"""Structured JSON audit logging for pdns-mcp.

Every successful commit_change execution appends one line to audit.jsonl.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from .models import PendingChange

log = logging.getLogger(__name__)


class AuditLogger:
    def __init__(self, path: str):
        self._path = Path(path)
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            log.warning(
                "Cannot create audit log directory %s — audit logging disabled",
                self._path.parent,
            )

    def log_commit(
        self,
        *,
        token: str,
        operation: str,
        zone: str,
        name: str | None,
        record_type: str | None,
        before: dict | None,
        after: dict | None,
        result: dict,
    ) -> str:
        """Write one audit record. Returns the audit_id."""
        import secrets
        audit_id = "audit_" + secrets.token_hex(4)

        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "audit_id": audit_id,
            # Store fingerprint only — raw token must never appear in logs
            "token_fp": PendingChange.fingerprint(token),
            "operation": operation,
            "zone": zone,
            "name": name,
            "type": record_type,
            "before": before,
            "after": after,
            "result": result.get("status", "ok"),
        }

        try:
            with open(self._path, "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as exc:
            # Never let audit failures break the commit path — but do log clearly
            log.error("AUDIT WRITE FAILED (commit succeeded): %s", exc)

        return audit_id


class NullAuditLogger(AuditLogger):
    """No-op audit logger for testing."""
    def __init__(self):
        pass

    def log_commit(self, **kwargs) -> str:
        return "audit_test"
