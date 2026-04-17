"""Validators for PowerDNS zone metadata kinds.

Each metadata kind has specific value constraints. These validators
surface problems before we send anything to PDNS, giving Claude
clear error messages rather than opaque API failures.

Reference: https://doc.powerdns.com/authoritative/domainmetadata.html
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable

from .models import ValidationResult


# ---------------------------------------------------------------------------
# Metadata kind registry
# ---------------------------------------------------------------------------

@dataclass
class MetadataKindSpec:
    kind: str
    description: str
    multi_value: bool           # True = list of values; False = single value
    writable: bool = True       # False = read-only via HTTP API (PDNS sets it)
    http_api_available: bool = True  # False = not accessible via metadata HTTP endpoint at all
    use_zone_property: str = ""  # non-empty = use PUT /zones/{id} with this field name instead
    validator: Callable[[list[str]], ValidationResult] | None = None
    example: str = ""


def _ok() -> ValidationResult:
    return ValidationResult(passed=True)


# ---------------------------------------------------------------------------
# Individual validators
# ---------------------------------------------------------------------------

def _validate_ip_or_cidr_list(values: list[str]) -> ValidationResult:
    """Validate a list of IP addresses, CIDRs, or IP[:port] pairs.

    Valid: 192.0.2.1, 192.0.2.0/24, 2001:db8::/32,
           192.0.2.1:5300, [2001:db8::1]:5300
    Invalid: 192.0.2.1:notaport, 192.0.2.1:99999
    """
    result = _ok()
    for v in values:
        addr_part, port_part = _extract_addr(v)
        try:
            ipaddress.ip_network(addr_part, strict=False)
        except ValueError:
            try:
                ipaddress.ip_address(addr_part)
            except ValueError:
                result.fail(f"Invalid IP address or CIDR: {v!r}")
                continue
        if port_part is not None:
            try:
                port = int(port_part)
                if not (1 <= port <= 65535):
                    result.fail(f"Port {port} out of range 1-65535 in: {v!r}")
            except ValueError:
                result.fail(f"Invalid port {port_part!r} in: {v!r}")
    return result


def _extract_addr(value: str) -> tuple[str, str | None]:
    """Extract (address, port_or_none) from an IP, CIDR, or IP:port string."""
    # IPv6 with port: [addr]:port
    if value.startswith("["):
        addr_part = value[1:].split("]", 1)[0]
        port_part = value.split("]:", 1)[1] if "]:" in value else None
        return addr_part, port_part
    # IPv6 without port: two or more colons and no brackets → pure IPv6 or CIDR
    colon_count = value.count(":")
    if colon_count >= 2:
        return value, None
    # IPv4 with optional port: addr or addr:port
    if colon_count == 1:
        addr, port = value.rsplit(":", 1)
        return addr, port
    return value, None


def _validate_single_ip_or_cidr(values: list[str]) -> ValidationResult:
    result = _ok()
    if len(values) != 1:
        result.fail(f"Expected exactly one value, got {len(values)}")
        return result
    return _validate_ip_or_cidr_list(values)


def _validate_hostname_list(values: list[str]) -> ValidationResult:
    result = _ok()
    label_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    for v in values:
        name = v.rstrip(".")
        if not name:
            result.fail("Empty hostname value")
            continue
        for label in name.split("."):
            if not label_re.match(label):
                result.fail(f"Invalid hostname: {v!r}")
                break
    return result


def _validate_single_value(values: list[str]) -> ValidationResult:
    result = _ok()
    if len(values) != 1:
        result.fail(f"This metadata kind requires exactly one value, got {len(values)}")
    return result


def _validate_bool_flag(values: list[str]) -> ValidationResult:
    result = _ok()
    if len(values) != 1:
        result.fail(f"Expected exactly one value ('0' or '1'), got {len(values)}")
        return result
    if values[0] not in ("0", "1"):
        result.fail(f"Value must be '0' or '1', got {values[0]!r}")
    return result


def _validate_soa_edit(values: list[str]) -> ValidationResult:
    """SOA-EDIT and SOA-EDIT-API accept a fixed set of policy names."""
    valid = {
        "DEFAULT", "INCREASE", "EPOCH", "INCEPTION-EPOCH",
        "INCEPTION-INCREMENT", "INCEPTION-WEEK", "NONE", "",
    }
    result = _ok()
    if len(values) != 1:
        result.fail(f"Expected exactly one value, got {len(values)}")
        return result
    if values[0].upper() not in valid:
        result.warn(
            f"Value {values[0]!r} is not one of the standard SOA-EDIT policies "
            f"{sorted(v for v in valid if v)}. "
            "Accepted: DEFAULT, INCREASE, EPOCH, INCEPTION-EPOCH, "
            "INCEPTION-INCREMENT, INCEPTION-WEEK, NONE"
        )
    return result


def _validate_nsec3param(values: list[str]) -> ValidationResult:
    """NSEC3PARAM: '<hash-alg> <flags> <iterations> <salt>'  e.g. '1 0 0 -'"""
    result = _ok()
    if len(values) != 1:
        result.fail(f"Expected exactly one value, got {len(values)}")
        return result
    parts = values[0].split()
    if len(parts) != 4:
        result.fail(
            f"NSEC3PARAM must be '<algorithm> <flags> <iterations> <salt>', "
            f"got: {values[0]!r}"
        )
        return result
    alg_s, flags_s, iters_s, salt = parts
    try:
        alg = int(alg_s)
        if alg != 1:
            result.warn(f"NSEC3 algorithm {alg} is non-standard; expected 1 (SHA-1)")
    except ValueError:
        result.fail(f"Algorithm must be an integer, got {alg_s!r}")
    try:
        flags = int(flags_s)
        if flags not in (0, 1):
            result.warn(f"NSEC3 flags {flags} is unusual; expected 0 (default) or 1 (opt-out)")
    except ValueError:
        result.fail(f"Flags must be an integer, got {flags_s!r}")
    try:
        iters = int(iters_s)
        if iters > 150:
            result.warn(
                f"NSEC3 iteration count {iters} is high (recommended ≤ 0 for modern zones). "
                "High iteration counts degrade performance."
            )
    except ValueError:
        result.fail(f"Iterations must be an integer, got {iters_s!r}")
    if salt != "-" and not re.match(r"^[0-9a-fA-F]+$", salt):
        result.fail(f"Salt must be hex string or '-' (no salt), got {salt!r}")
    return result


def _validate_also_notify(values: list[str]) -> ValidationResult:
    """ALSO-NOTIFY: list of IP[:port] addresses."""
    return _validate_ip_or_cidr_list(values)


def _validate_axfr_source(values: list[str]) -> ValidationResult:
    """AXFR-SOURCE: single IP address (no CIDR, no port)."""
    result = _ok()
    if len(values) != 1:
        result.fail(f"Expected exactly one IP address, got {len(values)}")
        return result
    addr_part, port_part = _extract_addr(values[0])
    if port_part is not None:
        result.fail(f"AXFR-SOURCE must be a plain IP address with no port, got: {values[0]!r}")
        return result
    if "/" in addr_part:
        result.fail(f"AXFR-SOURCE must be a plain IP address, not a CIDR: {values[0]!r}")
        return result
    try:
        ipaddress.ip_address(addr_part)
    except ValueError:
        result.fail(f"Invalid IP address: {values[0]!r}")
    return result


# ---------------------------------------------------------------------------
# Kind registry
# ---------------------------------------------------------------------------

METADATA_KINDS: dict[str, MetadataKindSpec] = {
    # ----- Transfer / replication -----
    "ALLOW-AXFR-FROM": MetadataKindSpec(
        kind="ALLOW-AXFR-FROM",
        description="IP addresses/CIDRs allowed to AXFR this zone without TSIG.",
        multi_value=True,
        validator=_validate_ip_or_cidr_list,
        example="192.0.2.0/24",
    ),
    "ALSO-NOTIFY": MetadataKindSpec(
        kind="ALSO-NOTIFY",
        description="Extra IP[:port] addresses to NOTIFY on zone changes.",
        multi_value=True,
        validator=_validate_also_notify,
        example="192.0.2.1:5300",
    ),
    "AXFR-MASTER-TSIG": MetadataKindSpec(
        kind="AXFR-MASTER-TSIG",
        description="TSIG key name to use when retrieving this zone from its primary. Read-only via HTTP API — set via pdnsutil.",
        multi_value=False,
        writable=False,
        example="my-tsig-key",
    ),
    "AXFR-SOURCE": MetadataKindSpec(
        kind="AXFR-SOURCE",
        description="Source IP to use for outgoing AXFR/IXFR requests.",
        multi_value=False,
        validator=_validate_axfr_source,
        example="192.0.2.5",
    ),
    "IXFR": MetadataKindSpec(
        kind="IXFR",
        description="Set to '1' to attempt IXFR when retrieving zone updates.",
        multi_value=False,
        validator=_validate_bool_flag,
        example="1",
    ),
    "SLAVE-RENOTIFY": MetadataKindSpec(
        kind="SLAVE-RENOTIFY",
        description="Set to '1' to re-notify secondaries after receiving an AXFR.",
        multi_value=False,
        validator=_validate_bool_flag,
        example="1",
    ),
    "TSIG-ALLOW-AXFR": MetadataKindSpec(
        kind="TSIG-ALLOW-AXFR",
        description="TSIG key names that are allowed to AXFR this zone.",
        multi_value=True,
        validator=_validate_hostname_list,
        example="secondary-key",
    ),

    # ----- DNS Update (RFC 2136) -----
    "ALLOW-DNSUPDATE-FROM": MetadataKindSpec(
        kind="ALLOW-DNSUPDATE-FROM",
        description="IP addresses/CIDRs allowed to perform DNS updates.",
        multi_value=True,
        validator=_validate_ip_or_cidr_list,
        example="192.0.2.0/24",
    ),
    "FORWARD-DNSUPDATE": MetadataKindSpec(
        kind="FORWARD-DNSUPDATE",
        description="Forward DNS updates to the primary (secondary zones).",
        multi_value=False,
        validator=_validate_bool_flag,
        example="1",
    ),
    "NOTIFY-DNSUPDATE": MetadataKindSpec(
        kind="NOTIFY-DNSUPDATE",
        description="Send a NOTIFY after a successful DNS update.",
        multi_value=False,
        validator=_validate_bool_flag,
        example="1",
    ),
    "SOA-EDIT-DNSUPDATE": MetadataKindSpec(
        kind="SOA-EDIT-DNSUPDATE",
        description="SOA serial edit policy applied on DNS update.",
        multi_value=False,
        validator=_validate_soa_edit,
        example="INCEPTION-INCREMENT",
    ),
    "TSIG-ALLOW-DNSUPDATE": MetadataKindSpec(
        kind="TSIG-ALLOW-DNSUPDATE",
        description="TSIG key names allowed to perform DNS updates.",
        multi_value=True,
        validator=_validate_hostname_list,
        example="update-key",
    ),

    # ----- SOA serial management -----
    "SOA-EDIT": MetadataKindSpec(
        kind="SOA-EDIT",
        description=(
            "SOA serial edit policy for outgoing responses. "
            "Read-only via HTTP metadata API — set via pdnsutil or PUT /zones/{id}."
        ),
        multi_value=False,
        writable=False,
        use_zone_property="soa_edit",
        example="INCEPTION-INCREMENT",
    ),
    "SOA-EDIT-API": MetadataKindSpec(
        kind="SOA-EDIT-API",
        description=(
            "SOA serial edit policy applied on API changes. "
            "NOT available via the HTTP metadata endpoint — "
            "use preview_set_zone_properties with field 'soa_edit_api' instead."
        ),
        multi_value=False,
        writable=False,
        http_api_available=False,
        use_zone_property="soa_edit_api",
        example="DEFAULT",
    ),

    # ----- DNSSEC -----
    "API-RECTIFY": MetadataKindSpec(
        kind="API-RECTIFY",
        description=(
            "Auto-rectify zone on API changes (DNSSEC). "
            "NOT available via the HTTP metadata endpoint — "
            "use preview_set_zone_properties with field 'api_rectify' instead."
        ),
        multi_value=False,
        writable=False,
        http_api_available=False,
        use_zone_property="api_rectify",
        example="1",
    ),
    "NSEC3NARROW": MetadataKindSpec(
        kind="NSEC3NARROW",
        description=(
            "NSEC3 narrow mode. "
            "Read-only via HTTP metadata API — set via pdnsutil or PUT /zones/{id}."
        ),
        multi_value=False,
        writable=False,
        use_zone_property="nsec3narrow",
        example="1",
    ),
    "NSEC3PARAM": MetadataKindSpec(
        kind="NSEC3PARAM",
        description=(
            "NSEC3 parameters. Format: '<alg> <flags> <iterations> <salt>'. "
            "Read-only via HTTP metadata API — set via pdnsutil or PUT /zones/{id}."
        ),
        multi_value=False,
        writable=False,
        use_zone_property="nsec3param",
        example="1 0 0 -",
    ),
    "PRESIGNED": MetadataKindSpec(
        kind="PRESIGNED",
        description="Zone carries pre-made DNSSEC signatures. Set by PDNS on AXFR. "
                    "Delete this metadata to re-enable soa_edit_api serial incrementing. "
                    "Use preview_delete_metadata to clear it.",
        multi_value=False,
        writable=True,
        example="1",
    ),
    "PUBLISH-CDNSKEY": MetadataKindSpec(
        kind="PUBLISH-CDNSKEY",
        description="Publish CDNSKEY records. Set to '1' to enable.",
        multi_value=False,
        validator=_validate_bool_flag,
        example="1",
    ),
    "PUBLISH-CDS": MetadataKindSpec(
        kind="PUBLISH-CDS",
        description="Publish CDS records. Value is comma-separated digest algorithm numbers.",
        multi_value=True,
        example="2",
    ),

    # ----- LUA / scripting -----
    "ENABLE-LUA-RECORDS": MetadataKindSpec(
        kind="ENABLE-LUA-RECORDS",
        description=(
            "Allow LUA records in this zone. "
            "NOT available via the HTTP metadata endpoint — "
            "use preview_set_zone_properties with field 'enable_lua_records' or pdnsutil."
        ),
        multi_value=False,
        writable=False,
        http_api_available=False,
        example="1",
    ),
    "LUA-AXFR-SCRIPT": MetadataKindSpec(
        kind="LUA-AXFR-SCRIPT",
        description=(
            "Lua script for filtering incoming AXFRs. Use NONE to disable. "
            "Read-only via HTTP metadata API — set via pdnsutil."
        ),
        multi_value=False,
        writable=False,
        example="/etc/pdns/axfr-filter.lua",
    ),

    # ----- GSS-TSIG / Kerberos -----
    "GSS-ACCEPTOR-PRINCIPAL": MetadataKindSpec(
        kind="GSS-ACCEPTOR-PRINCIPAL",
        description="Kerberos principal for accepting GSS context (GSS-TSIG).",
        multi_value=False,
        validator=_validate_single_value,
        example="DNS/ns1.example.com@REALM",
    ),
    "GSS-ALLOW-AXFR-PRINCIPAL": MetadataKindSpec(
        kind="GSS-ALLOW-AXFR-PRINCIPAL",
        description="Kerberos principal allowed to perform AXFR (GSS-TSIG).",
        multi_value=True,
        example="host/secondary.example.com@REALM",
    ),

    # ----- Catalog zone (TRAP — must not be set via metadata API) -----
    # CATALOG looks like a metadata kind but is NOT. It is a field on the
    # Zone object (DomainInfo.catalog). Using set-meta CATALOG writes to the
    # metadata table which PDNS never reads when building catalog zone content.
    # The correct operation is PATCH /zones/{id} with {"catalog": "name."},
    # exposed here as the preview_set_catalog tool.
    "CATALOG": MetadataKindSpec(
        kind="CATALOG",
        description=(
            "NOT a metadata kind. Catalog zone membership is the `catalog` field "
            "on the Zone object, not a metadata entry. "
            "Use the preview_set_catalog tool instead — calling preview_set_metadata "
            "with kind='CATALOG' will appear to succeed but will have no effect on "
            "catalog zone membership."
        ),
        multi_value=False,
        writable=False,
        example="Use preview_set_catalog tool",
    ),
    "RFC1123-CONFORMANCE": MetadataKindSpec(
        kind="RFC1123-CONFORMANCE",
        description="Set to '1' to enforce RFC 1123 hostname conformance checks.",
        multi_value=False,
        validator=_validate_bool_flag,
        example="1",
    ),
    "SIGNALING-ZONE": MetadataKindSpec(
        kind="SIGNALING-ZONE",
        description="Marks this zone as a DNSSEC signaling zone.",
        multi_value=False,
        validator=_validate_bool_flag,
        example="1",
    ),
}

# Sorted list of all writable kind names for Claude to reference
WRITABLE_KINDS = sorted(k for k, v in METADATA_KINDS.items() if v.writable)
ALL_KINDS = sorted(METADATA_KINDS.keys())


# ---------------------------------------------------------------------------
# Public validation entry point
# ---------------------------------------------------------------------------

def validate_metadata(kind: str, values: list[str]) -> ValidationResult:
    """Validate metadata values for a given kind.

    Unknown kinds are allowed with a warning (PDNS supports arbitrary metadata).
    Read-only kinds are rejected.
    """
    result = ValidationResult(passed=True)

    if not values:
        return result.fail("Metadata values list cannot be empty. "
                           "To remove metadata, use preview_delete_metadata.")

    spec = METADATA_KINDS.get(kind.upper())

    # Special trap: CATALOG looks like a metadata kind but writes to the wrong place
    if kind.upper() == "CATALOG":
        return result.fail(
            "CATALOG is not a metadata kind. Catalog zone membership is stored in "
            "DomainInfo.catalog — a separate field that metadata writes never touch. "
            "Using set-meta CATALOG will appear to succeed but has no effect on catalog "
            "zone provisioning. Use the preview_set_catalog tool instead."
        )

    if spec is None:
        # Unknown kind — enforce X- prefix requirement per PDNS docs
        if not kind.upper().startswith("X-"):
            return result.fail(
                f"Unknown metadata kind {kind!r}. Custom metadata kinds must start with 'X-' "
                f"(e.g. 'X-MY-SETTING'). Known writable kinds: {', '.join(WRITABLE_KINDS[:10])}..."
            )
        result.warn(
            f"Storing custom metadata kind {kind!r}. "
            "PDNS will store it but it has no effect on server behaviour."
        )
        return result

    kind = spec.kind  # normalise case

    if not spec.http_api_available:
        redirect = (
            f" Use preview_set_zone_properties with field '{spec.use_zone_property}' instead."
            if spec.use_zone_property else ""
        )
        return result.fail(
            f"Metadata kind {kind!r} is not accessible via the HTTP metadata endpoint — "
            f"PowerDNS does not expose it there.{redirect}"
        )

    if not spec.writable:
        redirect = (
            f" Use preview_set_zone_properties with field '{spec.use_zone_property}'."
            if spec.use_zone_property else " Use pdnsutil to set this value."
        )
        return result.fail(
            f"Metadata kind {kind!r} is read-only via the HTTP metadata endpoint.{redirect}"
        )

    if not spec.multi_value and len(values) > 1:
        result.fail(
            f"Metadata kind {kind!r} only accepts a single value, "
            f"but {len(values)} values were provided."
        )
        return result

    if spec.validator:
        type_result = spec.validator(values)
        result.passed = result.passed and type_result.passed
        result.errors.extend(type_result.errors)
        result.warnings.extend(type_result.warnings)

    return result
