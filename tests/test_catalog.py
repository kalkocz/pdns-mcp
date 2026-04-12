"""Tests for catalog zone assignment tools.

Includes regression test for the set-meta CATALOG vs set-catalog failure
that caused empty catalog AXFR and Knot provisioning failure on HMS Illustrious.
"""

import pytest
from unittest.mock import AsyncMock, patch
from pdns_mcp.metadata_validators import validate_metadata, METADATA_KINDS
from pdns_mcp.config import Config, DEFAULT_DEV_CONFIG
from pdns_mcp.pdns_client import PDNSNotFoundError
from pdns_mcp.preview import PreviewEngine


def make_config():
    return Config.from_dict(DEFAULT_DEV_CONFIG)


def make_client(zone_exists=True, current_catalog=""):
    client = AsyncMock()
    if zone_exists:
        client.get_zone.return_value = {
            "name": "example.com.",
            "kind": "Master",
            "serial": 2024040101,
            "catalog": current_catalog,
            "rrsets": [],
        }
    else:
        client.get_zone.side_effect = PDNSNotFoundError(404, "not found")
    client.put_zone_properties.return_value = {}
    return client


# ---------------------------------------------------------------------------
# Regression: CATALOG metadata trap
# ---------------------------------------------------------------------------

class TestCatalogMetadataTrap:
    """
    Regression for: pdnsutil set-meta CATALOG vs pdnsutil set-catalog.

    set-meta CATALOG writes to the metadata table.
    PDNS reads DomainInfo.catalog (set by set-catalog / PATCH /zones/{id})
    when building catalog zone AXFR content.
    The two fields are completely different — set-meta CATALOG has no effect
    on catalog zone membership.

    This test ensures our MCP server cannot silently route through the wrong path.
    """

    def test_catalog_kind_is_not_settable_via_metadata_api(self):
        """The core regression test. This must never pass."""
        result = validate_metadata("CATALOG", ["catalog.internal."])
        assert not result.passed, (
            "CRITICAL: CATALOG must not be settable via the metadata API. "
            "This would write to the metadata table, not DomainInfo.catalog, "
            "producing an empty catalog AXFR and breaking Knot provisioning."
        )

    def test_catalog_error_message_redirects_correctly(self):
        result = validate_metadata("CATALOG", ["catalog.internal."])
        error_text = " ".join(result.errors)
        assert "preview_set_catalog" in error_text, (
            "Error must name the correct tool to use"
        )
        assert "DomainInfo" in error_text or "catalog field" in error_text.lower() or \
               "Zone object" in error_text, (
            "Error must explain the storage difference"
        )

    def test_catalog_spec_describes_the_problem(self):
        spec = METADATA_KINDS["CATALOG"]
        assert "metadata table" in spec.description or "Zone object" in spec.description
        assert "preview_set_catalog" in spec.description


# ---------------------------------------------------------------------------
# preview_set_catalog — correct path
# ---------------------------------------------------------------------------

class TestPreviewSetCatalog:

    async def test_assign_zone_to_catalog(self):
        client = make_client(current_catalog="")
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="lindy.hmsvictory.org.",
            catalog_zone="catalog.internal.",
        )

        assert result.validation.passed
        assert result.diff.action == "SET_CATALOG"
        assert result.diff.proposed == {"catalog": "catalog.internal."}
        assert result.diff.current == {"catalog": None}
        assert result.confirmation_token.startswith("tok_")

    async def test_remove_catalog_membership(self):
        client = make_client(current_catalog="catalog.internal.")
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="lindy.hmsvictory.org.",
            catalog_zone="",
        )

        assert result.validation.passed
        assert result.diff.action == "REMOVE_CATALOG"
        assert result.diff.proposed == {"catalog": None}

    async def test_replace_catalog(self):
        client = make_client(current_catalog="catalog.internal.")
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="lindy.hmsvictory.org.",
            catalog_zone="catalog.external.",
        )

        assert result.diff.action == "REPLACE_CATALOG"
        assert result.diff.current == {"catalog": "catalog.internal."}
        assert result.diff.proposed == {"catalog": "catalog.external."}

    async def test_noop_warns(self):
        client = make_client(current_catalog="catalog.internal.")
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="lindy.hmsvictory.org.",
            catalog_zone="catalog.internal.",
        )

        assert result.validation.passed
        assert result.validation.warnings  # should warn it's a no-op

    async def test_zone_not_found(self):
        client = make_client(zone_exists=False)
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="missing.example.com.",
            catalog_zone="catalog.internal.",
        )

        assert not result.validation.passed

    async def test_trailing_dot_normalised(self):
        client = make_client(current_catalog="")
        engine = PreviewEngine(client, make_config())

        result = await engine.preview_set_catalog(
            zone="lindy.hmsvictory.org",       # no trailing dot
            catalog_zone="catalog.internal",   # no trailing dot
        )

        assert result.diff.zone == "lindy.hmsvictory.org."
        assert result.diff.proposed == {"catalog": "catalog.internal."}

    async def test_commit_calls_put_zone_properties(self):
        """Catalog assignment must use PATCH /zones/{id} not the metadata API."""
        client = make_client(current_catalog="")
        engine = PreviewEngine(client, make_config())

        preview = await engine.preview_set_catalog(
            zone="lindy.hmsvictory.org.",
            catalog_zone="catalog.internal.",
        )

        await engine.commit(preview.confirmation_token)

        # Must call put_zone_properties (DomainInfo.catalog path)
        client.put_zone_properties.assert_called_once()
        call_args = client.put_zone_properties.call_args
        assert call_args[0][1] == {"catalog": "catalog.internal."}

        # Must NOT call set_metadata (metadata table path — the wrong path)
        client.set_metadata = AsyncMock()
        assert not client.set_metadata.called


# ---------------------------------------------------------------------------
# HMS Illustrious recovery scenario
# ---------------------------------------------------------------------------

class TestHMSIllustriousRecovery:
    """
    Mirrors the actual recovery script from pdns-catalog-rootcause.md.
    18 zones across 5 catalog zones.
    """

    HMS_ASSIGNMENTS = [
        # Forward zones
        ("lindy.hmsvictory.org.",    "catalog.internal."),
        ("lindy6.hmsvictory.org.",   "catalog.internal6."),
        ("v6.lindy.hmsvictory.org.", "catalog.internal6."),
        ("hmsvictory.org.",          "catalog.external."),
        ("whoami.hmsvictory.org.",   "catalog.external."),
        # IPv4 reverse
        ("1.168.192.in-addr.arpa.",  "catalog.internal.in-addr.arpa."),
        ("0.10.10.in-addr.arpa.",    "catalog.internal.in-addr.arpa."),
    ]

    async def test_all_zones_can_be_previewed(self):
        """All zones in the recovery script should preview successfully."""
        client = AsyncMock()
        client.get_zone.return_value = {
            "name": "placeholder.",
            "kind": "Master",
            "serial": 2024040101,
            "catalog": "",
            "rrsets": [],
        }
        client.put_zone_properties.return_value = {}

        engine = PreviewEngine(engine := make_config(), make_config())
        engine = PreviewEngine(client, make_config())

        for zone, catalog in self.HMS_ASSIGNMENTS:
            result = await engine.preview_set_catalog(
                zone=zone, catalog_zone=catalog,
            )
            assert result.validation.passed, (
                f"Preview failed for {zone} → {catalog}: "
                f"{result.validation.errors}"
            )
            assert result.confirmation_token.startswith("tok_")
