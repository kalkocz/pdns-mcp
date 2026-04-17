"""Preview engine for pdns-mcp.

Responsibilities:
  - Fetch current state from PDNS
  - Run validation
  - Compute a human-readable diff
  - Generate and store a confirmation token
  - Surface warnings (PTR orphan, last NS, etc.)
"""

from __future__ import annotations

import asyncio
import time
import logging
from typing import TYPE_CHECKING

from .models import (
    Diff,
    PendingChange,
    PreviewResult,
    RRSet,
    Record,
    ValidationResult,
)
from .validators import validate_record
from .metadata_validators import validate_metadata, METADATA_KINDS, WRITABLE_KINDS
import httpx

from .pdns_client import PDNSClient, PDNSError, PDNSNotFoundError, PDNSTransportError

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger(__name__)

# How long to keep used tokens before evicting (seconds)
_USED_TOKEN_RETAIN = 300


class TokenError(Exception):
    """Raised by commit() for token-related failures."""
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class PreviewEngine:
    """Stateful preview/commit engine. One instance per server process."""

    def __init__(self, client: PDNSClient, config: "Config"):
        self._client = client
        self._config = config
        self._pending: dict[str, PendingChange] = {}

    # ------------------------------------------------------------------
    # Public preview API
    # ------------------------------------------------------------------

    async def preview_set_record(
        self,
        zone: str,
        name: str,
        rtype: str,
        ttl: int,
        records: list[str],
        comment: str = "",
    ) -> PreviewResult:
        zone = self._canonical(zone)
        name = self._canonical(name)
        rtype = rtype.upper()

        self._check_readonly(zone)

        # Validate content before touching PDNS
        val = validate_record(
            rtype,
            records,
            ttl,
            self._config.policy.min_ttl,
            self._config.policy.max_ttl,
        )
        if not val.passed:
            return self._validation_failed(val, zone, name, rtype)

        # Fetch current state — also captures serial for stale-preview detection
        current_rrset: RRSet | None = None
        zone_serial: int | None = None
        try:
            zone_data = await self._client.get_zone(zone)
            zone_serial = zone_data.get("serial")
            for rs in zone_data.get("rrsets", []):
                if rs["name"] == name and rs["type"] == rtype:
                    current_rrset = RRSet.from_pdns(rs)
                    break
        except PDNSNotFoundError:
            val.fail(f"Zone {zone!r} does not exist in PowerDNS")
            return self._validation_failed(val, zone, name, rtype)

        # Extra warnings
        await self._warn_ptr_orphan(val, zone, name, rtype, records)
        if rtype == "NS":
            self._warn_last_ns(val, current_rrset, records)

        action = "CREATE" if current_rrset is None else "REPLACE"

        # Build PDNS payload
        new_rrset = RRSet(
            name=name,
            type=rtype,
            ttl=ttl,
            records=[Record(r) for r in records],
        )
        pdns_payload = {"rrsets": [new_rrset.to_pdns_patch("REPLACE")]}

        if comment:
            pdns_payload["rrsets"][0]["comments"] = [
                {"content": comment, "account": "pdns-mcp"}
            ]

        # Store snapshot of current state for audit trail
        pdns_payload["_snapshot_before"] = _rrset_to_dict(current_rrset)

        diff = Diff(
            zone=zone,
            name=name,
            record_type=rtype,
            action=action,
            current=_rrset_to_dict(current_rrset),
            proposed={"ttl": ttl, "records": records},
        )

        return self._make_preview(
            val, diff,
            zone_serial=zone_serial,
            operation="SET",
            zone=zone,
            name=name,
            record_type=rtype,
            pdns_payload=pdns_payload,
            pdns_method="PATCH",
            pdns_url_path=f"/zones/{zone}",
        )

    async def preview_delete_record(
        self,
        zone: str,
        name: str,
        rtype: str,
    ) -> PreviewResult:
        zone = self._canonical(zone)
        name = self._canonical(name)
        rtype = rtype.upper()

        self._check_readonly(zone)

        val = ValidationResult(passed=True)

        current_rrset: RRSet | None = None
        zone_serial: int | None = None
        try:
            zone_data = await self._client.get_zone(zone)
            zone_serial = zone_data.get("serial")
            for rs in zone_data.get("rrsets", []):
                if rs["name"] == name and rs["type"] == rtype:
                    current_rrset = RRSet.from_pdns(rs)
                    break
        except PDNSNotFoundError:
            val.fail(f"Zone {zone!r} does not exist in PowerDNS")
            return self._validation_failed(val, zone, name, rtype)

        if current_rrset is None:
            val.fail(
                f"Record {name} {rtype} does not exist in zone {zone} — nothing to delete"
            )
            return self._validation_failed(val, zone, name, rtype)

        # Warn if deleting last NS
        if rtype == "NS":
            self._warn_last_ns(val, current_rrset, [])

        pdns_payload = {
            "rrsets": [{
                "name": name,
                "type": rtype,
                "changetype": "DELETE",
            }]
        }

        diff = Diff(
            zone=zone,
            name=name,
            record_type=rtype,
            action="DELETE",
            current=_rrset_to_dict(current_rrset),
            proposed=None,
        )

        return self._make_preview(
            val, diff,
            zone_serial=zone_serial,
            operation="DELETE",
            zone=zone,
            name=name,
            record_type=rtype,
            pdns_payload=pdns_payload,
            pdns_method="PATCH",
            pdns_url_path=f"/zones/{zone}",
        )

    async def preview_create_zone(
        self,
        zone: str,
        kind: str = "Native",
        nameservers: list[str] | None = None,
    ) -> PreviewResult:
        zone = self._canonical(zone)
        self._check_readonly(zone)

        val = ValidationResult(passed=True)
        kind = kind.capitalize()
        if kind not in ("Native", "Master", "Slave"):
            val.fail(f"Zone kind must be Native, Master, or Slave — got {kind!r}")
            return self._validation_failed(val, zone, None, None)

        # Check zone doesn't already exist
        try:
            await self._client.get_zone(zone)
            val.fail(f"Zone {zone!r} already exists")
            return self._validation_failed(val, zone, None, None)
        except PDNSNotFoundError:
            pass  # expected — zone should not exist yet

        ns = [self._canonical(n) for n in (nameservers or [])]
        pdns_payload = {
            "name": zone,
            "kind": kind,
            "nameservers": ns,
            "soa_edit_api": "INCEPTION-INCREMENT",
        }

        diff = Diff(
            zone=zone,
            name=None,
            record_type=None,
            action="CREATE_ZONE",
            current=None,
            proposed={"kind": kind, "nameservers": ns},
        )

        return self._make_preview(
            val, diff,
            operation="CREATE_ZONE",
            zone=zone,
            name=None,
            record_type=None,
            pdns_payload=pdns_payload,
            pdns_method="POST",
            pdns_url_path="/zones",
        )

    async def preview_delete_zone(self, zone: str) -> PreviewResult:
        zone = self._canonical(zone)
        self._check_readonly(zone)

        val = ValidationResult(passed=True)

        try:
            zone_data = await self._client.get_zone(zone)
        except PDNSNotFoundError:
            val.fail(f"Zone {zone!r} does not exist")
            return self._validation_failed(val, zone, None, None)

        rrset_count = len(zone_data.get("rrsets", []))
        if rrset_count > 10:
            val.warn(
                f"Zone {zone!r} contains {rrset_count} rrsets — "
                "this deletion cannot be undone"
            )

        diff = Diff(
            zone=zone,
            name=None,
            record_type=None,
            action="DELETE_ZONE",
            current={"rrset_count": rrset_count},
            proposed=None,
        )

        return self._make_preview(
            val, diff,
            operation="DELETE_ZONE",
            zone=zone,
            name=None,
            record_type=None,
            pdns_payload={},
            pdns_method="DELETE",
            pdns_url_path=f"/zones/{zone}",
        )

    async def preview_flush_cache(self, domain: str = "") -> PreviewResult:
        val = ValidationResult(passed=True)
        target = self._canonical(domain) if domain else "(all)"

        diff = Diff(
            zone=target,
            name=None,
            record_type=None,
            action="FLUSH_CACHE",
            current=None,
            proposed={"domain": target},
        )

        return self._make_preview(
            val, diff,
            operation="FLUSH_CACHE",
            zone=target,
            name=None,
            record_type=None,
            pdns_payload={"domain": domain},
            pdns_method="PUT",
            pdns_url_path="/cache/flush",
        )

    async def preview_notify_zone(self, zone: str) -> PreviewResult:
        zone = self._canonical(zone)
        val = ValidationResult(passed=True)

        try:
            await self._client.get_zone(zone)
        except PDNSNotFoundError:
            val.fail(f"Zone {zone!r} does not exist")
            return self._validation_failed(val, zone, None, None)

        diff = Diff(
            zone=zone,
            name=None,
            record_type=None,
            action="NOTIFY",
            current=None,
            proposed={"zone": zone},
        )

        return self._make_preview(
            val, diff,
            operation="NOTIFY",
            zone=zone,
            name=None,
            record_type=None,
            pdns_payload={},
            pdns_method="PUT",
            pdns_url_path=f"/zones/{zone}/notify",
        )

    async def preview_set_catalog(
        self,
        zone: str,
        catalog_zone: str,
    ) -> PreviewResult:
        """Preview assigning a zone to a catalog producer zone (PDNS 4.9+).

        Pass catalog_zone="" to remove catalog membership.

        In PowerDNS 4.9+, catalog membership is the `catalog` field on the
        Zone object. It is NOT zone metadata — do not use set-meta CATALOG.
        The correct API call is PATCH /zones/{id} with {"catalog": "name."}.
        """
        zone = self._canonical(zone)
        self._check_readonly(zone)

        val = ValidationResult(passed=True)

        # Normalize catalog zone name
        if catalog_zone:
            catalog_zone = self._canonical(catalog_zone)

        try:
            zone_data = await self._client.get_zone(zone)
        except PDNSNotFoundError:
            val.fail(f"Zone {zone!r} does not exist")
            return self._validation_failed(val, zone, None, None)

        current_catalog = zone_data.get("catalog", "") or ""
        zone_serial = zone_data.get("serial")

        if catalog_zone and not catalog_zone.endswith("."):
            val.fail("Catalog zone name must end with '.'")
            return self._validation_failed(val, zone, None, None)

        if current_catalog == catalog_zone:
            if catalog_zone:
                val.warn(
                    f"Zone {zone!r} is already a member of catalog {catalog_zone!r} — "
                    "this operation is a no-op"
                )
            else:
                val.warn(f"Zone {zone!r} has no catalog membership — nothing to remove")

        action = "REMOVE_CATALOG" if not catalog_zone else (
            "REPLACE_CATALOG" if current_catalog else "SET_CATALOG"
        )

        diff = Diff(
            zone=zone,
            name=None,
            record_type=None,
            action=action,
            current={"catalog": current_catalog or None},
            proposed={"catalog": catalog_zone or None},
        )

        return self._make_preview(
            val, diff,
            zone_serial=zone_serial,
            operation="SET_CATALOG",
            zone=zone,
            name=None,
            record_type=None,
            pdns_payload={"catalog": catalog_zone},
            pdns_method="PATCH",
            pdns_url_path=f"/zones/{zone}",
        )

    async def preview_set_zone_properties(
        self,
        zone: str,
        properties: dict,
    ) -> PreviewResult:
        """Preview updating zone-level fields via PUT /zones/{id}."""
        zone = self._canonical(zone)
        self._check_readonly(zone)

        val = ValidationResult(passed=True)

        ALLOWED_FIELDS = {
            "kind", "masters", "catalog", "account",
            "soa_edit", "soa_edit_api", "api_rectify",
            "dnssec", "nsec3param",
        }
        unknown = set(properties.keys()) - ALLOWED_FIELDS
        if unknown:
            val.warn(
                f"Unknown zone fields {sorted(unknown)} will be ignored by PowerDNS. "
                f"Writable fields: {sorted(ALLOWED_FIELDS)}"
            )

        if "catalog" in properties:
            val.warn(
                "Setting 'catalog' via preview_set_zone_properties works, but "
                "preview_set_catalog is preferred — it fetches current state and "
                "produces a clearer diff."
            )

        try:
            zone_data = await self._client.get_zone(zone)
        except PDNSNotFoundError:
            val.fail(f"Zone {zone!r} does not exist")
            return self._validation_failed(val, zone, None, None)

        zone_serial = zone_data.get("serial")

        # Build diff showing before/after for the touched fields only
        current = {k: zone_data.get(k) for k in properties if k in zone_data}
        proposed = dict(properties)

        diff = Diff(
            zone=zone,
            name=None,
            record_type=None,
            action="SET_ZONE_PROPERTIES",
            current=current,
            proposed=proposed,
        )

        return self._make_preview(
            val, diff,
            zone_serial=zone_serial,
            operation="SET_ZONE_PROPERTIES",
            zone=zone,
            name=None,
            record_type=None,
            pdns_payload=properties,
            pdns_method="PUT",
            pdns_url_path=f"/zones/{zone}",
        )

    async def preview_set_metadata(
        self,
        zone: str,
        kind: str,
        values: list[str],
    ) -> PreviewResult:
        """Preview setting (replacing) a zone metadata kind."""
        zone = self._canonical(zone)
        kind = kind.upper()
        self._check_readonly(zone)

        val = validate_metadata(kind, values)
        if not val.passed:
            return self._validation_failed(val, zone, None, None)

        # Fetch current state
        current_values: list[str] = []
        try:
            await self._client.get_zone(zone)  # confirm zone exists
            try:
                meta = await self._client.get_metadata(zone, kind)
                current_values = meta.get("metadata", [])
            except PDNSNotFoundError:
                pass  # kind doesn't exist yet — that's fine, we're creating it
        except PDNSNotFoundError:
            val.fail(f"Zone {zone!r} does not exist")
            return self._validation_failed(val, zone, None, None)

        action = "CREATE_METADATA" if not current_values else "REPLACE_METADATA"

        if current_values == values:
            val.warn(
                f"Metadata {kind!r} already has the same value(s) — "
                "this operation is a no-op"
            )

        diff = Diff(
            zone=zone,
            name=None,
            record_type=kind,
            action=action,
            current={"kind": kind, "values": current_values} if current_values else None,
            proposed={"kind": kind, "values": values},
        )

        return self._make_preview(
            val, diff,
            operation="SET_METADATA",
            zone=zone,
            name=None,
            record_type=kind,
            pdns_payload={"kind": kind, "values": values},
            pdns_method="PUT",
            pdns_url_path=f"/zones/{zone}/metadata/{kind}",
        )

    async def preview_delete_metadata(
        self,
        zone: str,
        kind: str,
    ) -> PreviewResult:
        """Preview deleting all values for a zone metadata kind."""
        zone = self._canonical(zone)
        kind = kind.upper()
        self._check_readonly(zone)

        val = ValidationResult(passed=True)

        # Check kind is not read-only
        spec = METADATA_KINDS.get(kind)
        if spec and not spec.writable:
            val.fail(f"Metadata kind {kind!r} is read-only and cannot be deleted.")
            return self._validation_failed(val, zone, None, None)

        current_values: list[str] = []
        try:
            await self._client.get_zone(zone)
            try:
                meta = await self._client.get_metadata(zone, kind)
                current_values = meta.get("metadata", [])
            except PDNSNotFoundError:
                val.fail(
                    f"Metadata kind {kind!r} does not exist on zone {zone!r} — "
                    "nothing to delete"
                )
                return self._validation_failed(val, zone, None, None)
        except PDNSNotFoundError:
            val.fail(f"Zone {zone!r} does not exist")
            return self._validation_failed(val, zone, None, None)

        diff = Diff(
            zone=zone,
            name=None,
            record_type=kind,
            action="DELETE_METADATA",
            current={"kind": kind, "values": current_values},
            proposed=None,
        )

        return self._make_preview(
            val, diff,
            operation="DELETE_METADATA",
            zone=zone,
            name=None,
            record_type=kind,
            pdns_payload={"kind": kind},
            pdns_method="DELETE",
            pdns_url_path=f"/zones/{zone}/metadata/{kind}",
        )

    # ------------------------------------------------------------------
    # Commit
    # ------------------------------------------------------------------

    async def commit(self, token: str) -> dict:
        """Execute a previewed change. Raises TokenError on any token problem."""
        self._evict_old_tokens()

        fp = PendingChange.fingerprint(token)  # safe to log
        change = self._pending.get(token)
        if change is None:
            raise TokenError("token_not_found", f"Token {fp} not found")
        if change.used:
            raise TokenError("token_already_used", f"Token {fp} already used")
        if change.is_expired(self._config.policy.token_ttl_seconds):
            raise TokenError("token_expired", f"Token {fp} has expired")

        # Re-validate zone serial to catch stale previews
        if change.zone_serial is not None and change.operation in ("SET", "DELETE"):
            try:
                current_zone = await self._client.get_zone(change.zone)
                current_serial = current_zone.get("serial")
                if current_serial != change.zone_serial:
                    raise TokenError(
                        "stale_preview",
                        f"Zone {change.zone!r} serial changed since preview "
                        f"(was {change.zone_serial}, now {current_serial}). "
                        "Please re-run the preview tool.",
                    )
            except PDNSNotFoundError:
                raise TokenError(
                    "zone_gone",
                    f"Zone {change.zone!r} no longer exists",
                )

        change.consume()

        try:
            result = await self._execute(change)
        except Exception as exc:
            log.error("PDNS error during commit fp=%s: %s", fp, exc)
            raise

        log.info(
            "commit ok fp=%s op=%s zone=%s name=%s type=%s",
            fp,
            change.operation,
            change.zone,
            change.name,
            change.record_type,
        )
        return result

    async def _execute(self, change: PendingChange) -> dict:
        """Dispatch to the correct PDNS call based on the pending change."""
        client = self._client

        if change.operation in ("SET", "DELETE"):
            await client.patch_rrsets(change.zone, change.pdns_payload["rrsets"])
            # Notify slaves and refresh serial — both best-effort, never fail the write
            serial: int | None = None
            try:
                await client.notify_zone(change.zone)
            except Exception as exc:
                log.warning("Post-write notify_zone failed (write succeeded): %s", exc)
            try:
                zone_data = await client.get_zone(change.zone)
                serial = zone_data.get("serial")
            except Exception as exc:
                log.warning("Post-write serial refresh failed (write succeeded): %s", exc)
            return {
                "status": "ok",
                "operation": change.operation,
                "zone": change.zone,
                "name": change.name,
                "type": change.record_type,
                "serial": serial,
            }

        elif change.operation == "CREATE_ZONE":
            result = await client.create_zone(change.pdns_payload)
            return {
                "status": "ok",
                "operation": change.operation,
                "zone": change.zone,
                "serial": result.get("serial"),
            }

        elif change.operation == "DELETE_ZONE":
            await client.delete_zone(change.zone)
            return {
                "status": "ok",
                "operation": change.operation,
                "zone": change.zone,
            }

        elif change.operation == "SET_CATALOG":
            # PDNS 4.9+: catalog membership is a zone-level property, not metadata.
            # PATCH /zones/{id} with {"catalog": "catalog-zone."} or {"catalog": ""}
            await client.put_zone_properties(
                change.zone, {"catalog": change.pdns_payload["catalog"]}
            )
            catalog = change.pdns_payload["catalog"]
            return {
                "status": "ok",
                "operation": change.operation,
                "zone": change.zone,
                "catalog": catalog or None,
                "note": (
                    f"Zone {change.zone!r} assigned to catalog {catalog!r}"
                    if catalog
                    else f"Zone {change.zone!r} catalog membership removed"
                ),
            }

        elif change.operation == "FLUSH_CACHE":
            result = await client.flush_cache(change.pdns_payload.get("domain", ""))
            return {"status": "ok", "operation": change.operation, **result}

        elif change.operation == "NOTIFY":
            result = await client.notify_zone(change.zone)
            return {"status": "ok", "operation": change.operation, **result}

        elif change.operation == "SET_ZONE_PROPERTIES":
            result = await client.put_zone_properties(change.zone, change.pdns_payload)
            return {
                "status": "ok",
                "operation": change.operation,
                "zone": change.zone,
                "updated_fields": list(change.pdns_payload.keys()),
                "serial": result.get("serial") if isinstance(result, dict) else None,
            }

        elif change.operation == "SET_METADATA":
            kind = change.pdns_payload["kind"]
            values = change.pdns_payload["values"]
            result = await client.set_metadata(change.zone, kind, values)
            return {
                "status": "ok",
                "operation": change.operation,
                "zone": change.zone,
                "kind": kind,
                "values": result.get("metadata", values),
            }

        elif change.operation == "DELETE_METADATA":
            kind = change.pdns_payload["kind"]
            await client.delete_metadata(change.zone, kind)
            return {
                "status": "ok",
                "operation": change.operation,
                "zone": change.zone,
                "kind": kind,
            }

        else:
            raise ValueError(f"Unknown operation: {change.operation}")

    # ------------------------------------------------------------------
    # Warning helpers
    # ------------------------------------------------------------------

    async def _warn_ptr_orphan(
        self,
        val: ValidationResult,
        zone: str,
        name: str,
        rtype: str,
        records: list[str],
    ) -> None:
        """Warn if changing an A record that has a corresponding PTR."""
        if rtype != "A":
            return
        # Best-effort: search for a PTR with the old IP — don't fail on error
        try:
            current = await self._client.get_rrset(zone, name, "A")
            if current:
                for rec in current.records:
                    results = await self._client.search(
                        rec.content, max_results=5, object_type="record"
                    )
                    for r in results:
                        if r.get("type") == "PTR":
                            val.warn(
                                f"A record {name} currently has IP {rec.content} "
                                f"with a PTR record in zone {r.get('zone', '?')} — "
                                "PTR will not be updated automatically"
                            )
                            return
        except (PDNSError, PDNSNotFoundError, PDNSTransportError, httpx.RequestError):
            # Best-effort check — network/API errors must not block the preview
            pass

    @staticmethod
    def _warn_last_ns(
        val: ValidationResult,
        current: RRSet | None,
        new_records: list[str],
    ) -> None:
        """Warn if an NS operation would leave the zone with fewer than 2 NS."""
        if not new_records:
            val.warn("Deleting NS records — ensure the zone retains at least 2 NS records")
        elif len(new_records) < 2:
            val.warn(
                f"Setting only {len(new_records)} NS record(s) — "
                "most registrars require at least 2"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_readonly(self, zone: str) -> None:
        if self._config.is_readonly_zone(zone):
            raise PermissionError(
                f"Zone {zone!r} is in the readonly_zones list and cannot be modified"
            )

    def _make_preview(
        self,
        val: ValidationResult,
        diff: Diff,
        zone_serial: int | None = None,
        **change_kwargs,
    ) -> PreviewResult:
        token = PendingChange.new_token()
        change = PendingChange(token=token, zone_serial=zone_serial, **change_kwargs)
        self._pending[token] = change

        return PreviewResult(
            diff=diff,
            validation=val,
            confirmation_token=token,
            expires_in_seconds=self._config.policy.token_ttl_seconds,
        )

    def _validation_failed(
        self,
        val: ValidationResult,
        zone: str,
        name: str | None,
        rtype: str | None,
    ) -> PreviewResult:
        """Return a PreviewResult with no token when validation fails."""
        diff = Diff(
            zone=zone, name=name, record_type=rtype,
            action="NONE", current=None, proposed=None,
        )
        return PreviewResult(
            diff=diff,
            validation=val,
            confirmation_token="",
            expires_in_seconds=0,
        )

    def _evict_old_tokens(self) -> None:
        """Remove stale tokens from the pending store.

        Policy:
        - Used tokens: evict after _USED_TOKEN_RETAIN seconds (audit grace period)
        - Unused expired tokens: evict after token_ttl * 3 (enough time for
          commit() to return 'token_expired' rather than 'token_not_found',
          while still bounding memory growth from abandoned previews)
        """
        now = time.monotonic()
        ttl = self._config.policy.token_ttl_seconds
        to_delete = [
            tok for tok, ch in self._pending.items()
            if (ch.used and ch.used_at and (now - ch.used_at) > _USED_TOKEN_RETAIN)
            or (not ch.used and (now - ch.created_at) > ttl * 3)
        ]
        for tok in to_delete:
            del self._pending[tok]
        if to_delete:
            log.debug("Evicted %d stale token(s)", len(to_delete))

    async def start_background_eviction(self, interval_seconds: int = 60) -> None:
        """Spawn a background task that periodically purges stale tokens.

        Call this from the server lifespan so eviction is not dependent
        on commit() being called — prevents unbounded growth from clients
        that call preview tools but never commit.
        """
        async def _loop() -> None:
            while True:
                await asyncio.sleep(interval_seconds)
                try:
                    self._evict_old_tokens()
                except Exception:
                    log.exception("Background token eviction failed")

        self._eviction_task = asyncio.create_task(_loop())
        log.info("Background token eviction started (interval=%ds)", interval_seconds)

    async def stop_background_eviction(self) -> None:
        task = getattr(self, "_eviction_task", None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    @staticmethod
    def _canonical(name: str) -> str:
        """Lowercase and ensure trailing dot — DNS names are case-insensitive."""
        name = name.lower()
        return name if name.endswith(".") else name + "."


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rrset_to_dict(rrset: RRSet | None) -> dict | None:
    if rrset is None:
        return None
    return {
        "ttl": rrset.ttl,
        "records": [r.content for r in rrset.records],
    }
