"""Pydantic models for Keycloak YAML configuration.

Example YAML structure:
    realm: celine

    scopes:
      - name: dataset.query
        description: Query datasets
      - name: dataset.admin
        description: Administer datasets

    clients:
      - client_id: svc-forecast
        name: Forecast Service
        description: Weather and energy forecasting
        secret: ${SVC_FORECAST_SECRET}  # optional, supports env vars
        scopes_prefix: forecast         # owns all forecast.* scopes
        default_scopes:
          - forecast.admin
          - dataset.query               # foreign scope → audience mapper added for svc-dataset-api
        optional_scopes:
          - digital-twin.values.read
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


# Pattern for ${VAR} and ${VAR:-default} interpolation
_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}")


def _resolve_env_str(s: str) -> str:
    """Resolve environment variable placeholders in a string."""
    def repl(m: re.Match[str]) -> str:
        var = m.group(1)
        default = m.group(3)
        val = os.getenv(var)
        if val is None or val == "":
            return default if default is not None else ""
        return val

    # Resolve repeatedly until stable (handles nested defaults)
    prev = None
    cur = s
    for _ in range(5):
        if cur == prev:
            break
        prev = cur
        cur = _ENV_PATTERN.sub(repl, cur)
    return cur


def _resolve_env(value: Any) -> Any:
    """Recursively resolve environment variables in a data structure."""
    if isinstance(value, str):
        return _resolve_env_str(value)
    if isinstance(value, list):
        return [_resolve_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _resolve_env(v) for k, v in value.items()}
    return value


class ScopeConfig(BaseModel):
    """Configuration for a client scope."""

    name: str = Field(..., description="Scope name (e.g., 'dataset.query')")
    description: str = Field(default="", description="Human-readable description")
    protocol: str = Field(default="openid-connect", description="Protocol (usually openid-connect)")

    # Additional attributes that can be set
    include_in_token_scope: bool = Field(
        default=True,
        description="Whether to include scope in access token",
    )


class ClientConfig(BaseModel):
    """Configuration for a Keycloak client."""

    client_id: str = Field(..., description="Client ID (unique identifier)")
    name: str = Field(default="", description="Display name")
    description: str = Field(default="", description="Description")

    # Secret management
    secret: str | None = Field(
        default=None,
        description="Client secret (if not provided, will be generated)",
    )

    # Scope ownership declaration.
    # Scopes starting with this prefix belong to this client.
    # Used to derive audience mappers: any other client referencing a foreign
    # scope prefix gets an audience mapper pointing to the owning client.
    # Clients without a scopes_prefix (e.g. celine-cli, mqtt-only clients)
    # are exempt from audience mapper generation entirely.
    scopes_prefix: str | None = Field(
        default=None,
        description=(
            "Scope prefix this client owns (e.g. 'dataset' owns all 'dataset.*' scopes). "
            "Drives automatic audience mapper generation for cross-service calls."
        ),
    )

    # Scope assignments
    default_scopes: list[str] = Field(
        default_factory=list,
        description="Scopes always included in tokens",
    )
    optional_scopes: list[str] = Field(
        default_factory=list,
        description="Scopes included only when explicitly requested",
    )

    # Service account settings (always enabled for this CLI)
    service_account_enabled: bool = Field(
        default=True,
        description="Enable service account (client credentials flow)",
    )

    @field_validator("name", mode="before")
    @classmethod
    def default_name_from_client_id(cls, v: str, info) -> str:
        """Use client_id as default name if not provided."""
        if not v and info.data.get("client_id"):
            return info.data["client_id"]
        return v or ""

    def scope_prefix_of(self, scope_name: str) -> str:
        """Extract the service prefix from a scope name (part before first '.')."""
        return scope_name.split(".")[0]

    def foreign_scope_prefixes(self) -> set[str]:
        """Return scope prefixes referenced by this client that are not its own.

        These are the services this client needs to call, and therefore the
        audience mappers that need to be added to its tokens.
        """
        if self.scopes_prefix is None:
            # Exempt clients — no audience mapping
            return set()

        all_scopes = list(self.default_scopes) + list(self.optional_scopes)
        prefixes: set[str] = set()
        for scope in all_scopes:
            prefix = self.scope_prefix_of(scope)
            if prefix != self.scopes_prefix:
                prefixes.add(prefix)
        return prefixes


class KeycloakConfig(BaseModel):
    """Top-level configuration for Keycloak sync."""

    realm: str = Field(default="celine", description="Target realm")

    scopes: list[ScopeConfig] = Field(
        default_factory=list,
        description="Client scopes to create/sync",
    )

    clients: list[ClientConfig] = Field(
        default_factory=list,
        description="Clients to create/sync",
    )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "KeycloakConfig":
        """Load configuration from a YAML file with env var interpolation."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        raw = yaml.safe_load(p.read_text())
        if not isinstance(raw, dict):
            raise ValueError(f"Config file must be a YAML mapping: {path}")

        # Resolve environment variables
        resolved = _resolve_env(raw)

        return cls.model_validate(resolved)

    def get_scope_names(self) -> set[str]:
        """Get all scope names defined in config."""
        return {s.name for s in self.scopes}

    def get_client_ids(self) -> set[str]:
        """Get all client IDs defined in config."""
        return {c.client_id for c in self.clients}

    def get_all_referenced_scopes(self) -> set[str]:
        """Get all scope names referenced by clients."""
        scopes: set[str] = set()
        for client in self.clients:
            scopes.update(client.default_scopes)
            scopes.update(client.optional_scopes)
        return scopes

    def build_prefix_to_client_map(self) -> dict[str, str]:
        """Build a mapping from scope prefix to owning client_id.

        Only clients with a scopes_prefix declared are included.

        Example:
            {"dataset": "svc-dataset-api", "digital-twin": "svc-digital-twin", ...}
        """
        return {
            c.scopes_prefix: c.client_id
            for c in self.clients
            if c.scopes_prefix is not None
        }

    def validate_scope_references(self) -> list[str]:
        """Check that all scopes referenced by clients are defined.

        Returns list of undefined scope names.
        """
        defined = self.get_scope_names()
        referenced = self.get_all_referenced_scopes()

        # Standard Keycloak scopes that don't need to be defined
        builtin_scopes = {
            "openid", "profile", "email", "address", "phone",
            "offline_access", "microprofile-jwt", "acr", "roles", "web-origins",
        }

        undefined = referenced - defined - builtin_scopes
        return sorted(undefined)