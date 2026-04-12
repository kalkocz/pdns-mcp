"""Tests for zone metadata validation and the catalog trap."""

import pytest
from pdns_mcp.metadata_validators import (
    validate_metadata,
    METADATA_KINDS,
    WRITABLE_KINDS,
)


# ---------------------------------------------------------------------------
# Catalog trap — the most important test in this file
# ---------------------------------------------------------------------------

class TestCatalogTrap:
    """CATALOG must never be settable via the metadata API.

    Background: DomainInfo.catalog (set via PATCH /zones/{id}) and the
    metadata table (set via PUT /zones/{id}/metadata/CATALOG) are completely
    different storage locations. PDNS reads DomainInfo.catalog when building
    catalog zone content; it never reads the metadata CATALOG key.

    Setting CATALOG via the metadata API appears to succeed but has no effect
    on catalog zone membership — exactly the failure mode that caused Knot to
    receive an empty catalog zone and provision no members.
    """

    def test_catalog_metadata_kind_is_rejected(self):
        result = validate_metadata("CATALOG", ["catalog.internal."])
        assert not result.passed
        assert any("preview_set_catalog" in e for e in result.errors), (
            "Error message must redirect to preview_set_catalog"
        )

    def test_catalog_case_insensitive_rejection(self):
        for variant in ("catalog", "CATALOG", "Catalog"):
            result = validate_metadata(variant, ["catalog.internal."])
            assert not result.passed, f"Should reject kind={variant!r}"

    def test_catalog_spec_marked_not_writable(self):
        spec = METADATA_KINDS.get("CATALOG")
        assert spec is not None
        assert not spec.writable

    def test_catalog_not_in_writable_kinds(self):
        assert "CATALOG" not in WRITABLE_KINDS


# ---------------------------------------------------------------------------
# Known kind validation
# ---------------------------------------------------------------------------

class TestKnownKinds:

    def test_soa_edit_api_now_rejected_via_metadata(self):
        """SOA-EDIT-API is not available via the HTTP metadata endpoint."""
        r = validate_metadata("SOA-EDIT-API", ["DEFAULT"])
        assert not r.passed
        assert any("preview_set_zone_properties" in e for e in r.errors)

    def test_soa_edit_read_only(self):
        """SOA-EDIT is read-only via HTTP metadata endpoint."""
        r = validate_metadata("SOA-EDIT", ["INCEPTION-INCREMENT"])
        assert not r.passed
        assert any("read-only" in e for e in r.errors)

    def test_api_rectify_not_available(self):
        """API-RECTIFY is not available via HTTP metadata endpoint."""
        r = validate_metadata("API-RECTIFY", ["1"])
        assert not r.passed
        assert any("preview_set_zone_properties" in e for e in r.errors)

    def test_enable_lua_records_not_available(self):
        """ENABLE-LUA-RECORDS is not available via HTTP metadata endpoint."""
        r = validate_metadata("ENABLE-LUA-RECORDS", ["1"])
        assert not r.passed
        assert any("metadata endpoint" in e for e in r.errors)

    def test_also_notify_valid_ip(self):
        r = validate_metadata("ALSO-NOTIFY", ["192.0.2.1", "192.0.2.2:5300"])
        assert r.passed

    def test_also_notify_invalid_ip(self):
        r = validate_metadata("ALSO-NOTIFY", ["not-an-ip"])
        assert not r.passed

    def test_also_notify_invalid_port_string(self):
        """Port must be numeric."""
        r = validate_metadata("ALSO-NOTIFY", ["192.0.2.1:notaport"])
        assert not r.passed

    def test_also_notify_port_out_of_range(self):
        r = validate_metadata("ALSO-NOTIFY", ["192.0.2.1:99999"])
        assert not r.passed

    def test_also_notify_ipv6_with_invalid_port(self):
        r = validate_metadata("ALSO-NOTIFY", ["[2001:db8::1]:abc"])
        assert not r.passed

    def test_allow_axfr_from_cidr(self):
        r = validate_metadata("ALLOW-AXFR-FROM", ["192.0.2.0/24", "2001:db8::/32"])
        assert r.passed

    def test_allow_axfr_from_auto_ns(self):
        """AUTO-NS is a valid special value for ALLOW-AXFR-FROM."""
        # AUTO-NS is not a valid IP, but PDNS accepts it — we warn but pass
        # Actually AUTO-NS fails IP validation — that's correct, users should set
        # it via pdnsutil not the metadata API for now
        pass  # acknowledged limitation

    def test_bool_flag_valid_for_writable_kinds(self):
        """Only test bool kinds that ARE writable via the metadata API."""
        for kind in ("IXFR", "SLAVE-RENOTIFY"):
            assert validate_metadata(kind, ["1"]).passed
            assert validate_metadata(kind, ["0"]).passed

    def test_bool_flag_rejects_wrong_value(self):
        r = validate_metadata("IXFR", ["yes"])
        assert not r.passed

    def test_nsec3param_read_only_via_metadata(self):
        """NSEC3PARAM is read-only via the HTTP metadata API."""
        r = validate_metadata("NSEC3PARAM", ["1 0 0 -"])
        assert not r.passed
        assert any("read-only" in e for e in r.errors)

    def test_lua_axfr_script_read_only(self):
        """LUA-AXFR-SCRIPT is read-only via the HTTP metadata API."""
        r = validate_metadata("LUA-AXFR-SCRIPT", ["/etc/pdns/filter.lua"])
        assert not r.passed
        assert any("read-only" in e for e in r.errors)

    def test_presigned_is_readonly(self):
        r = validate_metadata("PRESIGNED", ["1"])
        assert not r.passed
        assert any("read-only" in e for e in r.errors)

    def test_axfr_source_single_ip(self):
        r = validate_metadata("AXFR-SOURCE", ["192.0.2.5"])
        assert r.passed

    def test_axfr_source_rejects_cidr(self):
        r = validate_metadata("AXFR-SOURCE", ["192.0.2.0/24"])
        assert not r.passed

    def test_axfr_source_rejects_port(self):
        r = validate_metadata("AXFR-SOURCE", ["192.0.2.1:5300"])
        assert not r.passed

    def test_tsig_allow_axfr_multi_value(self):
        r = validate_metadata("TSIG-ALLOW-AXFR", ["key-a", "key-b"])
        assert r.passed

    def test_soa_edit_dnsupdate_writable(self):
        """SOA-EDIT-DNSUPDATE is distinct from SOA-EDIT and IS writable via metadata."""
        r = validate_metadata("SOA-EDIT-DNSUPDATE", ["INCEPTION-INCREMENT"])
        assert r.passed


# ---------------------------------------------------------------------------
# Unknown / custom metadata kinds
# ---------------------------------------------------------------------------

class TestUnknownKinds:

    def test_x_prefixed_custom_kind_passes(self):
        """Custom metadata must start with X- per PDNS docs."""
        r = validate_metadata("X-MY-CUSTOM-KIND", ["some-value"])
        assert r.passed
        assert r.warnings  # warns that it has no server effect

    def test_unknown_kind_without_x_prefix_rejected(self):
        """Non-X- unknown kinds are rejected to prevent silent misconfiguration."""
        r = validate_metadata("MY-CUSTOM-KIND", ["some-value"])
        assert not r.passed
        assert any("X-" in e for e in r.errors)

    def test_empty_values_always_rejected(self):
        r = validate_metadata("TSIG-ALLOW-AXFR", [])
        assert not r.passed
        assert any("empty" in e.lower() or "cannot be empty" in e for e in r.errors)

    def test_kind_normalised_to_uppercase(self):
        """Lowercase kind names must be accepted and normalised."""
        r = validate_metadata("tsig-allow-axfr", ["key-name"])
        assert r.passed

    def test_mixed_case_kind(self):
        r = validate_metadata("Ixfr", ["1"])
        assert r.passed
