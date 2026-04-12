"""pdns-mcp FastMCP server.

Exposes PowerDNS management as MCP tools with a mandatory
preview → commit workflow for all mutating operations.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .audit import AuditLogger, NullAuditLogger
from .config import Config, DEFAULT_DEV_CONFIG
from .models import PendingChange
from .pdns_client import PDNSClient, PDNSError, PDNSNotFoundError, PDNSTransportError
from .preview import PreviewEngine, TokenError

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App state — initialised in lifespan
# ---------------------------------------------------------------------------

_client: PDNSClient | None = None
_engine: PreviewEngine | None = None
_audit: AuditLogger | None = None
_config: Config | None = None


def _get_engine() -> PreviewEngine:
    if _engine is None:
        raise RuntimeError("Server not initialised")
    return _engine


def _get_audit() -> AuditLogger:
    if _audit is None:
        raise RuntimeError("Server not initialised")
    return _audit


# ---------------------------------------------------------------------------
# FastMCP app
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "pdns-mcp",
    instructions=(
        "PowerDNS DNS management. All writes require a preview step first. "
        "Always call a read or preview tool before commit_change."
    ),
)


# ---------------------------------------------------------------------------
# READ TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_zones() -> dict:
    """List all DNS zones managed by this PowerDNS server.

    Returns zone names, kind (Native/Master/Slave), serial number,
    and rrset count. Safe read-only operation.
    """
    try:
        zones = await _client.list_zones()
    except PDNSError as exc:
        return {"error": str(exc)}

    return {
        "zones": [
            {
                "name": z.get("name"),
                "kind": z.get("kind"),
                "serial": z.get("serial"),
                "catalog": z.get("catalog") or None,
                "dnssec": z.get("dnssec", False),
            }
            for z in zones
        ],
        "count": len(zones),
        "note": "Use get_zone(name) to retrieve full record contents.",
    }


@mcp.tool()
async def get_zone(zone: str) -> dict:
    """Get full contents of a DNS zone including all records.

    Args:
        zone: Zone name, e.g. "example.com." (trailing dot optional)
    """
    try:
        data = await _client.get_zone(zone)
    except PDNSNotFoundError:
        return {"error": f"Zone {zone!r} not found"}
    except PDNSError as exc:
        return {"error": str(exc)}

    rrsets = []
    for rs in data.get("rrsets", []):
        rrsets.append({
            "name": rs["name"],
            "type": rs["type"],
            "ttl": rs.get("ttl"),
            "records": [r["content"] for r in rs.get("records", [])],
        })

    return {
        "name": data.get("name"),
        "kind": data.get("kind"),
        "serial": data.get("serial"),
        "dnssec": data.get("dnssec", False),
        "rrsets": rrsets,
    }


@mcp.tool()
async def get_rrset(zone: str, name: str, record_type: str) -> dict:
    """Get a single DNS record set (rrset) from a zone.

    Use this before preview_set_record to see what currently exists.

    Args:
        zone: Zone name, e.g. "example.com."
        name: Record name, e.g. "www.example.com."
        record_type: Record type, e.g. "A", "CNAME", "MX", "TXT"
    """
    try:
        rrset = await _client.get_rrset(zone, name, record_type)
    except PDNSNotFoundError:
        return {"error": f"Zone {zone!r} not found"}
    except PDNSError as exc:
        return {"error": str(exc)}

    if rrset is None:
        return {
            "exists": False,
            "zone": zone,
            "name": name,
            "type": record_type,
        }

    return {
        "exists": True,
        "name": rrset.name,
        "type": rrset.type,
        "ttl": rrset.ttl,
        "records": [r.content for r in rrset.records],
    }


@mcp.tool()
async def search_records(query: str, max_results: int = 50) -> dict:
    """Search across all zones for records matching a query.

    Supports wildcard: * matches any sequence, ? matches one character.
    Example queries: "10.10.1.*", "*.example.com", "mail"

    Args:
        query: Search string, wildcards supported
        max_results: Maximum results to return (default 50)
    """
    try:
        results = await _client.search(query, max_results=max_results, object_type="record")
    except PDNSError as exc:
        return {"error": str(exc)}

    return {"results": results, "count": len(results)}


@mcp.tool()
async def get_server_stats() -> dict:
    """Get PowerDNS server health statistics.

    Returns key metrics: uptime, query rates, cache hit rate, backend latency.
    """
    try:
        raw = await _client.get_statistics()
    except PDNSError as exc:
        return {"error": str(exc)}

    # Pull out the most useful stats by name
    interesting = {
        "uptime", "udp-queries", "tcp-queries", "query-cache-hit",
        "query-cache-miss", "packetcache-hit", "packetcache-miss",
        "backend-queries", "servfail-answers", "nxdomain-answers",
    }
    stats = {
        s["name"]: s.get("value")
        for s in raw
        if s.get("name") in interesting
    }
    return {"statistics": stats}


# ---------------------------------------------------------------------------
# PREVIEW TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
async def preview_set_record(
    zone: str,
    name: str,
    record_type: str,
    ttl: int,
    records: list[str],
    comment: str = "",
) -> dict:
    """Preview creating or replacing a DNS record set.

    ALWAYS call this before commit_change. Returns a diff showing exactly
    what will change, any warnings, and a confirmation_token valid for 60s.

    If validation fails, no token is returned and the error explains why.

    Args:
        zone: Zone name, e.g. "waimea.local."
        name: Record name, e.g. "phantom.waimea.local."
        record_type: Record type: A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, CAA
        ttl: TTL in seconds (60–86400)
        records: List of record content strings.
                 A: ["10.10.1.5"]
                 MX: ["10 mail.example.com."]
                 TXT: ['"v=spf1 ~all"']
        comment: Optional comment stored with the record
    """
    engine = _get_engine()
    try:
        result = await engine.preview_set_record(
            zone=zone, name=name, rtype=record_type,
            ttl=ttl, records=records, comment=comment,
        )
    except PermissionError as exc:
        return {"error": "zone_readonly", "detail": str(exc)}
    except PDNSTransportError as exc:
        return {"error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"error": "pdns_error", "detail": str(exc)}

    return result.to_dict()


@mcp.tool()
async def preview_delete_record(
    zone: str,
    name: str,
    record_type: str,
) -> dict:
    """Preview deleting a DNS record set.

    Returns a diff and confirmation_token. Fails if the record does not exist.

    Args:
        zone: Zone name, e.g. "example.com."
        name: Record name, e.g. "old-host.example.com."
        record_type: Record type to delete, e.g. "A"
    """
    engine = _get_engine()
    try:
        result = await engine.preview_delete_record(zone=zone, name=name, rtype=record_type)
    except PermissionError as exc:
        return {"error": "zone_readonly", "detail": str(exc)}
    except PDNSTransportError as exc:
        return {"error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"error": "pdns_error", "detail": str(exc)}

    return result.to_dict()


@mcp.tool()
async def preview_create_zone(
    zone: str,
    kind: str = "Native",
    nameservers: list[str] | None = None,
) -> dict:
    """Preview creating a new DNS zone.

    Args:
        zone: Zone name with trailing dot, e.g. "newzone.local."
        kind: Zone type — Native, Master, or Slave (default: Native)
        nameservers: List of NS hostnames for the zone SOA
    """
    engine = _get_engine()
    try:
        result = await engine.preview_create_zone(
            zone=zone, kind=kind, nameservers=nameservers or [],
        )
    except PermissionError as exc:
        return {"error": "zone_readonly", "detail": str(exc)}
    except PDNSTransportError as exc:
        return {"error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"error": "pdns_error", "detail": str(exc)}

    return result.to_dict()


@mcp.tool()
async def preview_delete_zone(zone: str) -> dict:
    """Preview deleting an entire DNS zone and all its records.

    This is irreversible. The diff will show how many records will be lost.

    Args:
        zone: Zone name, e.g. "oldzone.local."
    """
    engine = _get_engine()
    try:
        result = await engine.preview_delete_zone(zone=zone)
    except PermissionError as exc:
        return {"error": "zone_readonly", "detail": str(exc)}
    except PDNSTransportError as exc:
        return {"error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"error": "pdns_error", "detail": str(exc)}

    return result.to_dict()


@mcp.tool()
async def preview_flush_cache(domain: str = "") -> dict:
    """Preview flushing the PowerDNS packet cache.

    Args:
        domain: Specific domain to flush, or empty string to flush everything
    """
    engine = _get_engine()
    result = await engine.preview_flush_cache(domain=domain)
    return result.to_dict()


@mcp.tool()
async def preview_notify_zone(zone: str) -> dict:
    """Preview sending NOTIFY to secondary nameservers for a zone.

    Args:
        zone: Zone name to notify, e.g. "example.com."
    """
    engine = _get_engine()
    try:
        result = await engine.preview_notify_zone(zone=zone)
    except PDNSTransportError as exc:
        return {"error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"error": "pdns_error", "detail": str(exc)}

    return result.to_dict()


@mcp.tool()
async def preview_set_catalog(zone: str, catalog_zone: str) -> dict:
    """Preview assigning or removing a zone's catalog producer membership.

    Catalog zones (RFC 9432) allow a primary nameserver to automatically
    provision secondary servers. In PowerDNS 4.9+, catalog membership is
    the `catalog` field on the Zone object — it is NOT zone metadata and
    must not be set with set-meta CATALOG (that field is ignored).

    Pass catalog_zone="" to remove catalog membership.

    Example: assign example.com. to be served under catalog.dns.example.:
      preview_set_catalog(zone="example.com.", catalog_zone="catalog.dns.example.")

    Args:
        zone: Member zone to assign, e.g. "example.com."
        catalog_zone: Producer catalog zone name, e.g. "catalog.dns.example."
                      Pass "" to remove catalog membership.
    """
    engine = _get_engine()
    try:
        result = await engine.preview_set_catalog(zone=zone, catalog_zone=catalog_zone)
    except PermissionError as exc:
        return {"error": "zone_readonly", "detail": str(exc)}
    except PDNSTransportError as exc:
        return {"error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"error": "pdns_error", "detail": str(exc)}

    return result.to_dict()


@mcp.tool()
async def preview_set_zone_properties(
    zone: str,
    properties: dict,
) -> dict:
    """Preview updating zone-level fields via PUT /zones/{id}.

    This handles settings that are Zone object fields, NOT metadata entries.
    Several metadata-looking kinds (SOA-EDIT-API, API-RECTIFY, NSEC3PARAM, etc.)
    are only accessible via this endpoint, not the metadata API.

    Writable zone fields:
      kind          : "Native", "Master", "Slave", "Producer", "Consumer"
      masters       : ["192.0.2.1"]  (for Slave/Consumer zones)
      catalog       : "catalog.internal."  (use preview_set_catalog instead)
      account       : "owner-name"
      soa_edit      : "INCEPTION-INCREMENT" (SOA serial policy on serving)
      soa_edit_api  : "DEFAULT"  (SOA serial policy on API changes)
      api_rectify   : true  (auto-rectify DNSSEC on changes)
      dnssec        : true  (enable DNSSEC signing)
      nsec3param    : "1 0 0 -"  (NSEC3 parameters)

    Example — enable auto-rectify and set SOA edit policy:
      preview_set_zone_properties(
        zone="example.com.",
        properties={"api_rectify": true, "soa_edit_api": "INCEPTION-INCREMENT"}
      )

    Args:
        zone:       Zone name, e.g. "example.com."
        properties: Dict of zone fields to update. Unknown fields are ignored by PDNS.
    """
    engine = _get_engine()
    try:
        result = await engine.preview_set_zone_properties(zone=zone, properties=properties)
    except PermissionError as exc:
        return {"error": "zone_readonly", "detail": str(exc)}
    except PDNSTransportError as exc:
        return {"error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"error": "pdns_error", "detail": str(exc)}

    return result.to_dict()


@mcp.tool()
async def preview_bulk_set_catalog(
    assignments: list[dict],
) -> dict:
    """Preview assigning multiple zones to catalog zones in one operation.

    Much more efficient than calling preview_set_catalog 18 times.
    Each assignment is previewed independently — failures are reported
    per-zone and do not block others. Returns one confirmation_token per
    valid assignment; pass all of them to commit_bulk_catalog.

    Note: commit_bulk_catalog commits each token sequentially and tolerates
    partial failure — it is NOT atomic. If one commit fails the rest continue.

    assignments format:
      [
        {"zone": "example.com.",   "catalog": "catalog.external."},
        {"zone": "internal.lan.",  "catalog": "catalog.internal."},
        {"zone": "old.example.",   "catalog": ""}   ← "" removes membership
      ]

    Example — full recovery for hmsvictory.org infrastructure:
      preview_bulk_set_catalog(assignments=[
        {"zone": "lindy.hmsvictory.org.",    "catalog": "catalog.internal."},
        {"zone": "lindy6.hmsvictory.org.",   "catalog": "catalog.internal6."},
        {"zone": "hmsvictory.org.",          "catalog": "catalog.external."},
        ...
      ])

    Args:
        assignments: List of {"zone": str, "catalog": str} dicts
    """
    from .pdns_client import PDNSTransportError

    engine = _get_engine()

    if not assignments:
        return {"error": "assignments list is empty"}

    results = []
    pending_tokens = []

    for item in assignments:
        zone = item.get("zone", "")
        catalog = item.get("catalog", "")
        if not zone:
            results.append({"zone": zone, "catalog": catalog,
                            "status": "error", "error": "zone name is required"})
            continue

        try:
            preview = await engine.preview_set_catalog(
                zone=zone, catalog_zone=catalog
            )
        except PermissionError as exc:
            results.append({"zone": zone, "catalog": catalog,
                            "status": "error", "error": f"zone_readonly: {exc}"})
            continue
        except (PDNSTransportError, PDNSError) as exc:
            results.append({"zone": zone, "catalog": catalog,
                            "status": "error", "error": str(exc)})
            continue

        d = preview.to_dict()
        if not d["validation"]["passed"]:
            results.append({
                "zone": zone, "catalog": catalog,
                "status": "validation_failed",
                "errors": d["validation"]["errors"],
                "warnings": d["validation"]["warnings"],
            })
        else:
            results.append({
                "zone": zone, "catalog": catalog,
                "status": "ready",
                "action": d["diff"]["action"],
                "current_catalog": (d["diff"].get("current") or {}).get("catalog"),
                "warnings": d["validation"]["warnings"],
                "token": d["confirmation_token"],
            })
            pending_tokens.append(d["confirmation_token"])

    ready_count = sum(1 for r in results if r["status"] == "ready")
    error_count = sum(1 for r in results if r["status"] in ("error", "validation_failed"))

    return {
        "summary": {
            "total": len(assignments),
            "ready": ready_count,
            "errors": error_count,
        },
        "assignments": results,
        "note": (
            f"{ready_count} assignment(s) ready. "
            "Each has its own confirmation_token — call commit_change separately "
            "for each token shown above, or use commit_bulk_catalog with all tokens."
            if ready_count > 0 else
            "No assignments are ready to commit."
        ),
    }


@mcp.tool()
async def commit_bulk_catalog(confirmation_tokens: list[str]) -> dict:
    """Commit multiple catalog assignments from preview_bulk_set_catalog.

    Pass all the confirmation_tokens returned by preview_bulk_set_catalog.
    Each is committed in order. If one fails (expired, stale), the rest
    continue — partial success is possible and is reported per-token.

    Args:
        confirmation_tokens: List of tokens from preview_bulk_set_catalog
    """
    from .pdns_client import PDNSTransportError

    engine = _get_engine()
    audit = _get_audit()

    if not confirmation_tokens:
        return {"error": "confirmation_tokens list is empty"}

    results = []
    for token in confirmation_tokens:
        pending = engine._pending.get(token)
        try:
            result = await engine.commit(token)
        except TokenError as exc:
            results.append({"token_fp": PendingChange.fingerprint(token),
                            "status": "error", "error": exc.code})
            continue
        except (PDNSTransportError, PDNSError) as exc:
            results.append({"token_fp": PendingChange.fingerprint(token),
                            "status": "error", "error": str(exc)})
            continue

        if pending:
            audit_id = audit.log_commit(
                token=token,
                operation=pending.operation,
                zone=pending.zone,
                name=pending.name,
                record_type=pending.record_type,
                before=None,
                after=pending.pdns_payload,
                result=result,
            )
            result["audit_id"] = audit_id

        results.append({
            "zone": result.get("zone"),
            "catalog": result.get("catalog"),
            "status": "ok",
            "operation": result.get("operation"),
            "audit_id": result.get("audit_id"),
        })

    ok = sum(1 for r in results if r["status"] == "ok")
    failed = sum(1 for r in results if r["status"] == "error")
    return {
        "summary": {"committed": ok, "failed": failed, "total": len(confirmation_tokens)},
        "results": results,
    }




@mcp.tool()
async def commit_change(confirmation_token: str) -> dict:
    """Execute a previewed DNS change.

    This is the ONLY tool that modifies PowerDNS. You must call a preview
    tool first to get a confirmation_token, review the diff and any warnings,
    then pass the token here.

    Tokens expire after 60 seconds and are single-use.

    Args:
        confirmation_token: Token returned by a preview tool (e.g. "tok_abc123...")
    """
    from .pdns_client import PDNSTransportError

    engine = _get_engine()
    audit = _get_audit()

    # Capture pending change before commit consumes it
    pending = engine._pending.get(confirmation_token)

    try:
        result = await engine.commit(confirmation_token)
    except TokenError as exc:
        return {"status": "error", "error": exc.code, "detail": str(exc)}
    except PermissionError as exc:
        return {"status": "error", "error": "zone_readonly", "detail": str(exc)}
    except PDNSTransportError as exc:
        return {"status": "error", "error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"status": "error", "error": "pdns_error", "detail": str(exc)}

    # Audit log — extract before from the diff snapshot stored at preview time
    if pending:
        before = pending.pdns_payload.get("_snapshot_before")  # set by preview engine
        audit_id = audit.log_commit(
            token=confirmation_token,
            operation=pending.operation,
            zone=pending.zone,
            name=pending.name,
            record_type=pending.record_type,
            before=before,
            after=pending.pdns_payload,
            result=result,
        )
        result["audit_id"] = audit_id

    return result


# ---------------------------------------------------------------------------
# NON-PREVIEW ADMIN TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
async def rectify_zone(zone: str) -> dict:
    """Rectify a zone's DNSSEC ordering. Safe, non-destructive.

    Required after manual DNSSEC changes. Does not modify record data.

    Args:
        zone: Zone name, e.g. "example.com."
    """
    try:
        result = await _client.rectify_zone(zone)
    except PDNSNotFoundError:
        return {"error": f"Zone {zone!r} not found"}
    except PDNSError as exc:
        return {"error": str(exc)}

    return {"status": "ok", "zone": zone, "result": result}


# ---------------------------------------------------------------------------
# METADATA TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_zone_metadata(zone: str) -> dict:
    """Get all metadata entries for a DNS zone.

    Zone metadata controls zone behaviour: transfer settings, SOA serial
    policies, DNSSEC options, TSIG keys, DNS update policies, and more.

    Args:
        zone: Zone name, e.g. "example.com."
    """
    try:
        metadata = await _client.list_metadata(zone)
    except PDNSNotFoundError:
        return {"error": f"Zone {zone!r} not found"}
    except PDNSTransportError as exc:
        return {"error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"error": str(exc)}

    # Annotate each entry with a description if we know the kind
    from .metadata_validators import METADATA_KINDS
    annotated = []
    for entry in metadata:
        kind = entry.get("kind", "")
        spec = METADATA_KINDS.get(kind.upper())
        annotated.append({
            "kind": kind,
            "values": entry.get("metadata", []),
            "description": spec.description if spec else "Custom metadata",
            "writable": spec.writable if spec else True,
        })

    return {"zone": zone, "metadata": annotated, "count": len(annotated)}


@mcp.tool()
async def preview_set_metadata(
    zone: str,
    kind: str,
    values: list[str],
) -> dict:
    """Preview setting (replacing) a zone metadata entry.

    Metadata controls zone behaviour — AXFR access, SOA serial policy,
    TSIG keys, DNS update permissions, DNSSEC parameters, and more.

    ALWAYS call get_zone_metadata first to see current values.
    This REPLACES all existing values for the kind — it does not append.

    IMPORTANT: Do NOT use this tool for catalog zone membership.
    'CATALOG' is not a metadata kind — it is stored in a separate Zone field.
    Using kind='CATALOG' here will appear to succeed but will NOT add the zone
    to a catalog. Use preview_set_catalog instead.

    Common kinds and examples:
      SOA-EDIT-API:       ["DEFAULT"] or ["INCEPTION-INCREMENT"]
      ALSO-NOTIFY:        ["192.0.2.1", "192.0.2.2:5300"]
      ALLOW-AXFR-FROM:    ["192.0.2.0/24", "2001:db8::/32"]
      TSIG-ALLOW-AXFR:    ["secondary-key-name"]
      AXFR-MASTER-TSIG:   ["primary-key-name"]
      API-RECTIFY:        ["1"]
      NSEC3PARAM:         ["1 0 0 -"]
      ENABLE-LUA-RECORDS: ["1"]

    Args:
        zone:   Zone name, e.g. "example.com."
        kind:   Metadata kind name, e.g. "SOA-EDIT-API"
        values: List of values (most kinds take a single-element list)
    """
    engine = _get_engine()
    try:
        result = await engine.preview_set_metadata(zone=zone, kind=kind, values=values)
    except PermissionError as exc:
        return {"error": "zone_readonly", "detail": str(exc)}
    except PDNSTransportError as exc:
        return {"error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"error": "pdns_error", "detail": str(exc)}

    return result.to_dict()


@mcp.tool()
async def preview_delete_metadata(zone: str, kind: str) -> dict:
    """Preview deleting all values for a zone metadata kind.

    This removes the metadata entry entirely from the zone.
    Use this to reset a setting to its PDNS global default.

    Args:
        zone: Zone name, e.g. "example.com."
        kind: Metadata kind to delete, e.g. "ALSO-NOTIFY"
    """
    engine = _get_engine()
    try:
        result = await engine.preview_delete_metadata(zone=zone, kind=kind)
    except PermissionError as exc:
        return {"error": "zone_readonly", "detail": str(exc)}
    except PDNSTransportError as exc:
        return {"error": "pdns_transport_error", "detail": str(exc)}
    except PDNSError as exc:
        return {"error": "pdns_error", "detail": str(exc)}

    return result.to_dict()


@mcp.tool()
async def list_metadata_kinds() -> dict:
    """List all known PowerDNS metadata kinds with descriptions.

    Use this to discover what metadata settings are available and
    what values they accept before calling preview_set_metadata.
    """
    from .metadata_validators import METADATA_KINDS, MetadataKindSpec
    kinds = []
    for kind, spec in sorted(METADATA_KINDS.items()):
        kinds.append({
            "kind": spec.kind,
            "description": spec.description,
            "multi_value": spec.multi_value,
            "writable": spec.writable,
            "example": spec.example,
        })
    return {"kinds": kinds, "count": len(kinds)}

def _make_auth_middleware(tokens: list[str]):
    """Return a Starlette middleware that enforces bearer token auth.

    Uses hmac.compare_digest to prevent timing attacks.
    If bearer_tokens is empty, all requests are allowed (dev mode).
    """
    from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    class BearerAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
            # Health / root paths exempt so load balancers can probe
            if request.url.path in ("/", "/health"):
                return await call_next(request)

            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return JSONResponse(
                    {"error": "unauthorized", "detail": "Bearer token required"},
                    status_code=401,
                )
            provided = auth_header[len("Bearer "):]
            if not any(
                hmac.compare_digest(provided, t) for t in tokens
            ):
                return JSONResponse(
                    {"error": "unauthorized", "detail": "Invalid bearer token"},
                    status_code=401,
                )
            return await call_next(request)

    return BearerAuthMiddleware


# ---------------------------------------------------------------------------
# Server startup / entry point
# ---------------------------------------------------------------------------

def _load_config() -> Config:
    config_path = os.environ.get("PDNS_MCP_CONFIG", "/etc/pdns-mcp/config.toml")
    try:
        cfg = Config.from_file(config_path)
    except FileNotFoundError:
        if os.environ.get("PDNS_MCP_ALLOW_DEV_DEFAULTS") == "1":
            log.warning(
                "Config file not found at %s — using dev defaults (PDNS_MCP_ALLOW_DEV_DEFAULTS=1). "
                "Never set this in production.",
                config_path,
            )
            return Config.from_dict(DEFAULT_DEV_CONFIG)
        raise SystemExit(
            f"ERROR: Config file not found at {config_path!r}. "
            "Create the config file or set PDNS_MCP_CONFIG to its path. "
            "Set PDNS_MCP_ALLOW_DEV_DEFAULTS=1 only for local development."
        )
    # Allow env var to override api_key (config may use OVERRIDE_VIA_ENV placeholder).
    # This lets the TOML ship without credentials while secrets are injected via
    # EnvironmentFile in the systemd unit (PDNS_MCP_API_KEY=...).
    env_api_key = os.environ.get("PDNS_MCP_API_KEY")
    if env_api_key:
        cfg.pdns.api_key = env_api_key
    return cfg


def main() -> None:
    """Entry point for the pdns-mcp server."""
    global _client, _engine, _audit, _config

    logging.basicConfig(level=logging.INFO)

    _config = _load_config()
    _client = PDNSClient(
        api_url=str(_config.pdns.api_url),
        api_key=_config.pdns.api_key,
        server_id=_config.pdns.server_id,
        timeout=_config.pdns.timeout_seconds,
    )
    _engine = PreviewEngine(_client, _config)
    _audit = AuditLogger(_config.server.audit_log_path)

    if _config.auth.auth_required:
        log.info("Bearer token auth enabled (%d token(s))", len(_config.auth.bearer_tokens))
    else:
        log.warning(
            "No bearer tokens configured — server is UNAUTHENTICATED. "
            "Set auth.bearer_tokens in config before exposing to the network."
        )

    log.info(
        "pdns-mcp starting on %s:%d — PDNS at %s — token store: in-memory / single-process",
        _config.server.host,
        _config.server.port,
        _config.pdns.api_url,
    )

    import uvicorn

    # Transport security: FastMCP's default TransportSecuritySettings only allows
    # localhost, which blocks AgentGateway proxy requests (Host: server_ip:port →
    # HTTP 421 Misdirected Request). When bound to 0.0.0.0/::, disable DNS
    # rebinding protection — bearer token auth is the security layer instead.
    if _config.server.host in ("0.0.0.0", "::"):
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )

    # Get the MCP ASGI app and its own lifespan (starts the StreamableHTTP session
    # manager task group). We must compose WITH it, not replace it — mounting inside
    # a new Starlette app causes Starlette.Mount to be opaque to lifecycle, so the
    # inner lifespan never fires → RuntimeError: Task group is not initialized.
    mcp_app = mcp.streamable_http_app()
    original_lifespan = mcp_app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app):
        await _engine.start_background_eviction(interval_seconds=60)
        log.info("pdns-mcp ready")
        async with original_lifespan(app):   # starts the MCP session manager task group
            yield
        await _engine.stop_background_eviction()
        await _client.close()
        log.info("pdns-mcp shutdown complete")

    mcp_app.router.lifespan_context = lifespan

    if _config.auth.auth_required:
        middleware_class = _make_auth_middleware(_config.auth.bearer_tokens)
        mcp_app.add_middleware(middleware_class)

    uvicorn.run(
        mcp_app,
        host=_config.server.host,
        port=_config.server.port,
        workers=1,   # token store is in-memory; never increase without shared state
        log_level=_config.server.log_level.lower(),
        access_log=True,
    )


if __name__ == "__main__":
    main()
