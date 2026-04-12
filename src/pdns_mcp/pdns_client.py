"""Async HTTP client for the PowerDNS Authoritative Server REST API.

This is the only module that holds the PDNS API key and makes
direct calls to PDNS. Everything else goes through this class.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .models import RRSet, Zone

log = logging.getLogger(__name__)


class PDNSError(Exception):
    """Raised when PowerDNS returns an error response."""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"PDNS {status_code}: {message}")


class PDNSNotFoundError(PDNSError):
    pass


class PDNSTransportError(PDNSError):
    """Raised when a network/transport error prevents reaching PowerDNS."""
    def __init__(self, message: str):
        super().__init__(0, message)


class PDNSClient:
    """Async client for the PowerDNS REST API."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        server_id: str = "localhost",
        timeout: float = 10.0,
    ):
        self._base = api_url.rstrip("/")
        self._server_id = server_id
        self._client = httpx.AsyncClient(
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            timeout=timeout,
        )

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base}/servers/{self._server_id}{path}"

    async def _get(self, path: str, params: dict | None = None) -> Any:
        try:
            resp = await self._client.get(self._url(path), params=params)
        except httpx.RequestError as exc:
            raise PDNSTransportError(f"Network error reaching PowerDNS: {exc}") from exc
        self._raise_for_status(resp)
        return resp.json()

    async def _patch(self, path: str, body: dict) -> Any:
        try:
            resp = await self._client.patch(self._url(path), json=body)
        except httpx.RequestError as exc:
            raise PDNSTransportError(f"Network error reaching PowerDNS: {exc}") from exc
        self._raise_for_status(resp)
        return resp.json() if resp.content else {}

    async def _post(self, path: str, body: dict) -> Any:
        try:
            resp = await self._client.post(self._url(path), json=body)
        except httpx.RequestError as exc:
            raise PDNSTransportError(f"Network error reaching PowerDNS: {exc}") from exc
        self._raise_for_status(resp)
        return resp.json() if resp.content else {}

    async def _delete(self, path: str) -> None:
        try:
            resp = await self._client.delete(self._url(path))
        except httpx.RequestError as exc:
            raise PDNSTransportError(f"Network error reaching PowerDNS: {exc}") from exc
        self._raise_for_status(resp)

    async def _put(
        self,
        path: str,
        *,
        body: dict | None = None,
        params: dict | None = None,
    ) -> Any:
        try:
            resp = await self._client.put(
                self._url(path), json=body or {}, params=params
            )
        except httpx.RequestError as exc:
            raise PDNSTransportError(f"Network error reaching PowerDNS: {exc}") from exc
        self._raise_for_status(resp)
        return resp.json() if resp.content else {}

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        if resp.status_code == 404:
            try:
                msg = resp.json().get("error", "not found")
            except Exception:
                msg = "not found"
            raise PDNSNotFoundError(404, msg)
        if resp.status_code >= 400:
            try:
                data = resp.json()
                msg = data.get("error", "") or ", ".join(data.get("errors", []))
            except Exception:
                msg = resp.text or f"HTTP {resp.status_code}"
            raise PDNSError(resp.status_code, msg)

    # ------------------------------------------------------------------
    # Zone operations
    # ------------------------------------------------------------------

    async def list_zones(self) -> list[dict]:
        """Return all zones (without rrsets for speed)."""
        return await self._get("/zones", params={"dnssec": "false"})

    async def get_zone(self, zone_name: str) -> dict:
        """Return full zone including all rrsets."""
        zone_id = self._zone_id(zone_name)
        return await self._get(f"/zones/{zone_id}")

    async def create_zone(self, body: dict) -> dict:
        return await self._post("/zones", body)

    async def delete_zone(self, zone_name: str) -> None:
        zone_id = self._zone_id(zone_name)
        await self._delete(f"/zones/{zone_id}")

    # ------------------------------------------------------------------
    # RRSet operations
    # ------------------------------------------------------------------

    async def put_zone_properties(self, zone_name: str, properties: dict) -> dict:
        """PUT zone-level fields (catalog, kind, masters, soa_edit, soa_edit_api,
        api_rectify, dnssec, nsec3param, account).

        Uses PUT /zones/{id}, NOT PATCH. PATCH is for RRsets/comments only.
        PUT zone fields returns 200 with the updated zone object.
        Unrecognised fields are silently ignored by PDNS.
        """
        zone_id = self._zone_id(zone_name)
        return await self._put(f"/zones/{zone_id}", body=properties)

    async def patch_rrsets(self, zone_name: str, rrsets: list[dict]) -> None:
        """Apply a list of rrset changes to a zone (PATCH semantics)."""
        zone_id = self._zone_id(zone_name)
        await self._patch(f"/zones/{zone_id}", {"rrsets": rrsets})

    async def get_rrset(
        self, zone_name: str, name: str, rtype: str
    ) -> RRSet | None:
        """
        Fetch a single rrset from a zone.
        Returns None if the zone exists but the rrset does not.
        Raises PDNSNotFoundError if the zone doesn't exist.
        """
        zone_data = await self.get_zone(zone_name)
        for rs in zone_data.get("rrsets", []):
            if rs["name"] == self._canonical(name) and rs["type"] == rtype.upper():
                return RRSet.from_pdns(rs)
        return None

    # ------------------------------------------------------------------
    # Metadata operations
    # ------------------------------------------------------------------

    async def list_metadata(self, zone_name: str) -> list[dict]:
        """Return all metadata entries for a zone."""
        zone_id = self._zone_id(zone_name)
        return await self._get(f"/zones/{zone_id}/metadata")

    async def get_metadata(self, zone_name: str, kind: str) -> dict:
        """Return a single metadata kind for a zone."""
        zone_id = self._zone_id(zone_name)
        return await self._get(f"/zones/{zone_id}/metadata/{kind}")

    async def set_metadata(self, zone_name: str, kind: str, values: list[str]) -> dict:
        """Replace all values for a metadata kind (PUT semantics — overwrites)."""
        zone_id = self._zone_id(zone_name)
        return await self._put(
            f"/zones/{zone_id}/metadata/{kind}",
            body={"kind": kind, "metadata": values},
        )

    async def delete_metadata(self, zone_name: str, kind: str) -> None:
        """Delete all values for a metadata kind."""
        zone_id = self._zone_id(zone_name)
        await self._delete(f"/zones/{zone_id}/metadata/{kind}")

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    async def search(
        self,
        query: str,
        max_results: int = 100,
        object_type: str = "all",
    ) -> list[dict]:
        return await self._get(
            "/search-data",
            params={"q": query, "max": max_results, "object_type": object_type},
        )

    # ------------------------------------------------------------------
    # Server operations
    # ------------------------------------------------------------------

    async def get_statistics(self) -> list[dict]:
        return await self._get("/statistics")

    async def flush_cache(self, domain: str = "") -> dict:
        """Flush the PDNS packet cache. domain is a query parameter per the API spec."""
        params: dict = {}
        if domain:
            params["domain"] = self._canonical(domain)
        return await self._put("/cache/flush", params=params or None)

    async def notify_zone(self, zone_name: str) -> dict:
        zone_id = self._zone_id(zone_name)
        return await self._put(f"/zones/{zone_id}/notify")

    async def rectify_zone(self, zone_name: str) -> dict:
        zone_id = self._zone_id(zone_name)
        return await self._put(f"/zones/{zone_id}/rectify")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _canonical(name: str) -> str:
        """Ensure name has a trailing dot and is lowercased (DNS is case-insensitive)."""
        name = name.lower()
        return name if name.endswith(".") else name + "."

    def _zone_id(self, zone_name: str) -> str:
        """
        PowerDNS zone IDs are the canonical (lowercased, trailing-dot) zone name.
        This is documented behavior, not an assumption.
        """
        return self._canonical(zone_name)
