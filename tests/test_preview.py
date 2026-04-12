"""Tests for the preview engine and token lifecycle."""

from __future__ import annotations

import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pdns_mcp.config import Config, DEFAULT_DEV_CONFIG
from pdns_mcp.models import RRSet, Record, Zone, PendingChange
from pdns_mcp.pdns_client import PDNSNotFoundError
from pdns_mcp.preview import PreviewEngine, TokenError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_config(**policy_overrides) -> Config:
    data = dict(DEFAULT_DEV_CONFIG)
    data["policy"] = {**data.get("policy", {}), **policy_overrides}
    return Config.from_dict(data)


def _rrset_to_wire(rrset: RRSet) -> dict:
    """Serialize an RRSet to the PDNS wire format that from_pdns() expects."""
    return {
        "name": rrset.name,
        "type": rrset.type,
        "ttl": rrset.ttl,
        "records": [{"content": r.content, "disabled": r.disabled} for r in rrset.records],
        "comments": rrset.comments,
    }


def make_client(
    *,
    zone_exists: bool = True,
    existing_rrset: RRSet | None = None,
    search_results: list | None = None,
    zone_data: dict | None = None,
) -> AsyncMock:
    client = AsyncMock()

    default_zone = zone_data or {
        "name": "example.com.",
        "kind": "Native",
        "serial": 2024040101,
        "rrsets": [_rrset_to_wire(existing_rrset)] if existing_rrset else [],
    }

    if zone_exists:
        client.get_zone.return_value = default_zone
        client.get_rrset.return_value = existing_rrset
    else:
        client.get_zone.side_effect = PDNSNotFoundError(404, "not found")
        client.get_rrset.side_effect = PDNSNotFoundError(404, "not found")

    client.search.return_value = search_results or []
    client.patch_rrsets.return_value = None
    client.delete_zone.return_value = None
    client.create_zone.return_value = {"name": "newzone.local.", "serial": 1}
    client.flush_cache.return_value = {"result": "Flushed cache"}
    client.notify_zone.return_value = {"result": "Sent notify"}
    return client


def make_rrset(name="phantom.example.com.", rtype="A", records=None, ttl=300):
    return RRSet(
        name=name,
        type=rtype,
        ttl=ttl,
        records=[Record(r) for r in (records or ["10.10.1.5"])],
    )


# ---------------------------------------------------------------------------
# preview_set_record
# ---------------------------------------------------------------------------

class TestPreviewSetRecord:

    async def test_create_new_record(self):
        client = make_client(existing_rrset=None)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="example.com.", name="new.example.com.",
            rtype="A", ttl=300, records=["10.10.1.10"],
        )

        assert result.validation.passed
        assert result.diff.action == "CREATE"
        assert result.diff.current is None
        assert result.diff.proposed["records"] == ["10.10.1.10"]
        assert result.confirmation_token.startswith("tok_")
        assert result.expires_in_seconds == 60

    async def test_replace_existing_record(self):
        existing = make_rrset(records=["10.10.1.5"])
        client = make_client(existing_rrset=existing)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="example.com.", name="phantom.example.com.",
            rtype="A", ttl=300, records=["10.10.1.10"],
        )

        assert result.diff.action == "REPLACE"
        assert result.diff.current["records"] == ["10.10.1.5"]
        assert result.diff.proposed["records"] == ["10.10.1.10"]

    async def test_validation_failure_no_token(self):
        client = make_client()
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="example.com.", name="host.example.com.",
            rtype="A", ttl=300, records=["not-an-ip"],
        )

        assert not result.validation.passed
        assert result.confirmation_token == ""
        assert result.expires_in_seconds == 0

    async def test_zone_not_found_fails(self):
        client = make_client(zone_exists=False)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="missing.com.", name="host.missing.com.",
            rtype="A", ttl=300, records=["10.0.0.1"],
        )

        assert not result.validation.passed
        assert any("does not exist" in e for e in result.validation.errors)

    async def test_readonly_zone_raises(self):
        client = make_client()
        engine = PreviewEngine(client, make_config(readonly_zones=["example.com."]))

        with pytest.raises(PermissionError, match="readonly"):
            await engine.preview_set_record(
                zone="example.com.", name="host.example.com.",
                rtype="A", ttl=300, records=["10.0.0.1"],
            )

    async def test_trailing_dot_normalised(self):
        """Zone and name without trailing dot should be normalised."""
        client = make_client(existing_rrset=None)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="example.com", name="host.example.com",  # no trailing dots
            rtype="A", ttl=300, records=["10.0.0.1"],
        )

        assert result.diff.zone == "example.com."
        assert result.diff.name == "host.example.com."

    async def test_low_ttl_generates_warning(self):
        client = make_client(existing_rrset=None)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="example.com.", name="host.example.com.",
            rtype="A", ttl=120, records=["10.0.0.1"],
        )

        assert result.validation.passed   # warning only, not error
        assert result.validation.warnings


# ---------------------------------------------------------------------------
# preview_delete_record
# ---------------------------------------------------------------------------

class TestPreviewDeleteRecord:

    async def test_delete_existing(self):
        existing = make_rrset()
        client = make_client(existing_rrset=existing)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_delete_record(
            zone="example.com.", name="phantom.example.com.", rtype="A",
        )

        assert result.validation.passed
        assert result.diff.action == "DELETE"
        assert result.diff.current["records"] == ["10.10.1.5"]
        assert result.diff.proposed is None
        assert result.confirmation_token.startswith("tok_")

    async def test_delete_nonexistent_fails(self):
        client = make_client(existing_rrset=None)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_delete_record(
            zone="example.com.", name="missing.example.com.", rtype="A",
        )

        assert not result.validation.passed
        assert result.confirmation_token == ""

    async def test_delete_readonly_zone_raises(self):
        existing = make_rrset()
        client = make_client(existing_rrset=existing)
        engine = PreviewEngine(client, make_config(readonly_zones=["example.com."]))

        with pytest.raises(PermissionError):
            await engine.preview_delete_record(
                zone="example.com.", name="phantom.example.com.", rtype="A",
            )


# ---------------------------------------------------------------------------
# preview_create_zone
# ---------------------------------------------------------------------------

class TestPreviewCreateZone:

    async def test_create_zone(self):
        client = make_client(zone_exists=False)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_create_zone(
            zone="newzone.local.",
            kind="Native",
            nameservers=["ns1.example.com.", "ns2.example.com."],
        )

        assert result.validation.passed
        assert result.diff.action == "CREATE_ZONE"
        assert result.confirmation_token.startswith("tok_")

    async def test_create_existing_zone_fails(self):
        client = make_client(zone_exists=True)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_create_zone(zone="example.com.")

        assert not result.validation.passed
        assert any("already exists" in e for e in result.validation.errors)

    async def test_invalid_kind_fails(self):
        client = make_client(zone_exists=False)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_create_zone(zone="newzone.local.", kind="Invalid")

        assert not result.validation.passed


# ---------------------------------------------------------------------------
# Token lifecycle
# ---------------------------------------------------------------------------

class TestTokenLifecycle:

    async def test_token_single_use(self):
        client = make_client(existing_rrset=None)
        engine = PreviewEngine(client, make_config())

        preview = await engine.preview_set_record(
            zone="example.com.", name="host.example.com.",
            rtype="A", ttl=300, records=["10.0.0.1"],
        )
        token = preview.confirmation_token

        # First commit succeeds
        await engine.commit(token)

        # Second commit fails
        with pytest.raises(TokenError) as exc_info:
            await engine.commit(token)
        assert exc_info.value.code == "token_already_used"

    async def test_token_expiry(self):
        client = make_client(existing_rrset=None)
        config = make_config(token_ttl_seconds=1)
        engine = PreviewEngine(client, config)

        preview = await engine.preview_set_record(
            zone="example.com.", name="host.example.com.",
            rtype="A", ttl=300, records=["10.0.0.1"],
        )
        token = preview.confirmation_token

        # Manually backdate the token's creation time
        engine._pending[token].created_at = time.monotonic() - 2

        with pytest.raises(TokenError) as exc_info:
            await engine.commit(token)
        assert exc_info.value.code == "token_expired"

    async def test_unknown_token_raises(self):
        client = make_client()
        engine = PreviewEngine(client, make_config())

        with pytest.raises(TokenError) as exc_info:
            await engine.commit("tok_doesnotexist")
        assert exc_info.value.code == "token_not_found"

    async def test_expired_unused_token_evicted_by_background(self):
        """Unused abandoned tokens must be cleaned up after grace period."""
        client = make_client(existing_rrset=None)
        config = make_config(token_ttl_seconds=1)
        engine = PreviewEngine(client, config)

        preview = await engine.preview_set_record(
            zone="example.com.", name="host.example.com.",
            rtype="A", ttl=300, records=["10.0.0.1"],
        )
        token = preview.confirmation_token
        assert token in engine._pending

        # Backdate past the grace period (ttl * 3 = 3s)
        engine._pending[token].created_at = time.monotonic() - 10

        engine._evict_old_tokens()

        assert token not in engine._pending

    async def test_stale_serial_rejected(self):
        """commit() must reject if zone serial changed since preview."""
        existing = make_rrset(records=["10.10.1.5"])
        client = make_client(existing_rrset=existing)
        engine = PreviewEngine(client, make_config())

        preview = await engine.preview_set_record(
            zone="example.com.", name="phantom.example.com.",
            rtype="A", ttl=300, records=["10.10.1.10"],
        )
        token = preview.confirmation_token

        # Simulate zone serial changing between preview and commit
        engine._pending[token].zone_serial = 2024040101
        client.get_zone.return_value = {
            "name": "example.com.",
            "serial": 2024040199,  # different serial
            "rrsets": [],  # contents don't matter for the serial check
        }

        with pytest.raises(TokenError) as exc_info:
            await engine.commit(token)
        assert exc_info.value.code == "stale_preview"

    async def test_matching_serial_allowed(self):
        """commit() must proceed if serial matches."""
        existing = make_rrset(records=["10.10.1.5"])
        client = make_client(existing_rrset=existing)
        engine = PreviewEngine(client, make_config())

        preview = await engine.preview_set_record(
            zone="example.com.", name="phantom.example.com.",
            rtype="A", ttl=300, records=["10.10.1.10"],
        )
        token = preview.confirmation_token
        serial = engine._pending[token].zone_serial

        # Serial unchanged
        client.get_zone.return_value = {
            "name": "example.com.",
            "serial": serial,
            "rrsets": [],
        }

        result = await engine.commit(token)
        assert result["status"] == "ok"


class TestPreviewResultSerialization:

    async def test_errors_included_in_to_dict(self):
        """Validation errors must appear in the serialised preview."""
        client = make_client()
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="example.com.", name="host.example.com.",
            rtype="A", ttl=300, records=["not-an-ip"],
        )
        d = result.to_dict()
        assert "errors" in d["validation"]
        assert d["validation"]["errors"]
        assert not d["validation"]["passed"]

    async def test_warnings_included_in_to_dict(self):
        client = make_client(existing_rrset=None)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="example.com.", name="host.example.com.",
            rtype="A", ttl=120, records=["10.0.0.1"],
        )
        d = result.to_dict()
        assert "warnings" in d["validation"]


class TestCaseSensitivity:

    async def test_readonly_zone_mixed_case_rejected(self):
        """DNS names are case-insensitive — EXAMPLE.COM. must match example.com."""
        client = make_client()
        engine = PreviewEngine(client, make_config(readonly_zones=["example.com."]))

        with pytest.raises(PermissionError):
            await engine.preview_set_record(
                zone="EXAMPLE.COM.", name="HOST.EXAMPLE.COM.",
                rtype="A", ttl=300, records=["10.0.0.1"],
            )

    async def test_record_name_lowercased_in_diff(self):
        client = make_client(existing_rrset=None)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="EXAMPLE.COM", name="WWW.EXAMPLE.COM",
            rtype="A", ttl=300, records=["10.0.0.1"],
        )
        assert result.diff.zone == "example.com."
        assert result.diff.name == "www.example.com."


class TestTokenSecurity:

    def test_token_entropy(self):
        """Tokens must be substantially longer than the old 8-hex-char format."""
        tokens = {PendingChange.new_token() for _ in range(50)}
        assert len(tokens) == 50  # all unique
        for t in tokens:
            assert t.startswith("tok_")
            # token_urlsafe(18) produces 24 base64 chars
            assert len(t) > 20, f"Token too short: {t!r}"

    def test_fingerprint_is_not_token(self):
        token = PendingChange.new_token()
        fp = PendingChange.fingerprint(token)
        assert fp != token
        assert fp.startswith("fp_")
        assert token not in fp

    def test_fingerprint_is_deterministic(self):
        token = PendingChange.new_token()
        assert PendingChange.fingerprint(token) == PendingChange.fingerprint(token)

    def test_different_tokens_different_fingerprints(self):
        t1 = PendingChange.new_token()
        t2 = PendingChange.new_token()
        assert PendingChange.fingerprint(t1) != PendingChange.fingerprint(t2)

    async def test_different_tokens_are_unique(self):
        client = make_client(existing_rrset=None)
        engine = PreviewEngine(client, make_config())

        tokens = set()
        for i in range(20):
            p = await engine.preview_set_record(
                zone="example.com.", name=f"host{i}.example.com.",
                rtype="A", ttl=300, records=["10.0.0.1"],
            )
            tokens.add(p.confirmation_token)

        assert len(tokens) == 20  # all unique


# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------

class TestWarnings:

    async def test_ptr_orphan_warning(self):
        existing = make_rrset(records=["10.10.1.5"])
        client = make_client(existing_rrset=existing)
        # Search returns a PTR for the old IP
        client.search.return_value = [{"type": "PTR", "zone": "10.10.in-addr.arpa."}]
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="example.com.", name="phantom.example.com.",
            rtype="A", ttl=300, records=["10.10.1.10"],
        )

        assert result.validation.passed
        assert any("PTR" in w for w in result.validation.warnings)

    async def test_ns_count_warning(self):
        client = make_client(existing_rrset=None)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_record(
            zone="example.com.", name="example.com.",
            rtype="NS", ttl=3600, records=["ns1.example.com."],  # only 1 NS
        )

        assert result.validation.passed
        assert any("NS" in w or "2" in w for w in result.validation.warnings)


class TestCatalogZone:

    def _make_client_with_catalog(self, current_catalog: str = "") -> AsyncMock:
        client = AsyncMock()
        client.get_zone.return_value = {
            "name": "example.com.",
            "kind": "Native",
            "serial": 2024040101,
            "catalog": current_catalog,
            "rrsets": [],
        }
        client.put_zone_properties = AsyncMock(return_value={})
        client.patch_rrsets = AsyncMock(return_value=None)
        client.search.return_value = []
        return client

    async def test_assign_catalog(self):
        client = self._make_client_with_catalog(current_catalog="")
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="example.com.", catalog_zone="catalog.dns.example."
        )

        assert result.validation.passed
        assert result.diff.action == "SET_CATALOG"
        assert result.diff.proposed == {"catalog": "catalog.dns.example."}
        assert result.diff.current == {"catalog": None}
        assert result.confirmation_token.startswith("tok_")

    async def test_replace_catalog(self):
        client = self._make_client_with_catalog(current_catalog="old-catalog.example.")
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="example.com.", catalog_zone="new-catalog.example."
        )

        assert result.validation.passed
        assert result.diff.action == "REPLACE_CATALOG"
        assert result.diff.current == {"catalog": "old-catalog.example."}
        assert result.diff.proposed == {"catalog": "new-catalog.example."}

    async def test_remove_catalog(self):
        client = self._make_client_with_catalog(current_catalog="catalog.dns.example.")
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="example.com.", catalog_zone=""
        )

        assert result.validation.passed
        assert result.diff.action == "REMOVE_CATALOG"
        assert result.diff.proposed == {"catalog": None}

    async def test_no_op_warns(self):
        client = self._make_client_with_catalog(current_catalog="catalog.dns.example.")
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="example.com.", catalog_zone="catalog.dns.example."
        )

        assert result.validation.passed
        assert any("no-op" in w for w in result.validation.warnings)

    async def test_zone_not_found(self):
        client = AsyncMock()
        client.get_zone.side_effect = PDNSNotFoundError(404, "not found")
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="missing.com.", catalog_zone="catalog.example."
        )

        assert not result.validation.passed
        assert result.confirmation_token == ""

    async def test_readonly_zone_raises(self):
        client = self._make_client_with_catalog()
        engine = PreviewEngine(client, make_config(readonly_zones=["example.com."]))

        with pytest.raises(PermissionError):
            await engine.preview_set_catalog(
                zone="example.com.", catalog_zone="catalog.example."
            )

    async def test_catalog_zone_name_normalised(self):
        """Catalog zone names must be lowercased and get a trailing dot."""
        client = self._make_client_with_catalog()
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="example.com", catalog_zone="CATALOG.DNS.EXAMPLE"
        )

        assert result.diff.proposed == {"catalog": "catalog.dns.example."}

    async def test_execute_set_catalog(self):
        """commit() must call put_zone_properties, not patch_rrsets."""
        client = self._make_client_with_catalog()
        engine = PreviewEngine(client, make_config())

        preview = await engine.preview_set_catalog(
            zone="example.com.", catalog_zone="catalog.dns.example."
        )
        token = preview.confirmation_token

        # Serial check path — return same serial
        serial = engine._pending[token].zone_serial
        client.get_zone.return_value["serial"] = serial

        result = await engine.commit(token)

        assert result["status"] == "ok"
        assert result["operation"] == "SET_CATALOG"
        assert result["catalog"] == "catalog.dns.example."
        # Must use the zone-property PATCH, not the rrset PATCH
        client.put_zone_properties.assert_called_once_with(
            "example.com.", {"catalog": "catalog.dns.example."}
        )
        client.patch_rrsets.assert_not_called()
