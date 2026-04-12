"""Configuration loading for pdns-mcp."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator


class PdnsConfig(BaseModel):
    api_url: AnyHttpUrl = AnyHttpUrl("http://127.0.0.1:8081/api/v1")
    api_key: str
    server_id: str = "localhost"
    timeout_seconds: float = 10.0


class ServerConfig(BaseModel):
    host: str = "127.0.0.1"   # bind localhost by default; set 0.0.0.0 explicitly for LAN
    port: int = 8765
    log_level: str = "INFO"
    audit_log_path: str = "/var/log/pdns-mcp/audit.jsonl"


class PolicyConfig(BaseModel):
    readonly_zones: list[str] = Field(default_factory=list)
    min_ttl: int = 60
    max_ttl: int = 86400
    token_ttl_seconds: int = 60
    require_preview_on_delete_zone: bool = True

    @field_validator("readonly_zones", mode="before")
    @classmethod
    def normalise_zones(cls, v: list[str]) -> list[str]:
        """Lowercase and ensure trailing dot on all readonly zone names."""
        return [
            (z.lower() if z.lower().endswith(".") else z.lower() + ".")
            for z in v
        ]


class AuthConfig(BaseModel):
    bearer_tokens: list[str] = Field(default_factory=list)

    @property
    def auth_required(self) -> bool:
        return len(self.bearer_tokens) > 0


class Config(BaseModel):
    pdns: PdnsConfig
    server: ServerConfig = Field(default_factory=ServerConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)

    @classmethod
    def from_file(cls, path: str | Path) -> "Config":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(p, "rb") as f:
            data = tomllib.load(f)
        return cls.model_validate(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        return cls.model_validate(data)

    def is_readonly_zone(self, zone: str) -> bool:
        z = zone.lower()
        z = z if z.endswith(".") else z + "."
        return z in self.policy.readonly_zones


# Default config used in tests / dev when no file is present
DEFAULT_DEV_CONFIG = {
    "pdns": {
        "api_url": "http://127.0.0.1:8081/api/v1",
        "api_key": "dev-key",
        "server_id": "localhost",
    },
    "policy": {
        "readonly_zones": [],
    },
    "auth": {
        "bearer_tokens": [],
    },
}
