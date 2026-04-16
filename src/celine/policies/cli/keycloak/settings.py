"""Keycloak CLI settings.

Settings can be provided via:
1. Environment variables (CELINE_KEYCLOAK_*)
2. CLI arguments (--admin-user, --admin-password, etc.)
3. Auto-loaded from .client.secrets.yaml (for celine-admin-cli)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

import secrets as _secrets

logger = logging.getLogger(__name__)

# Default secrets file path
DEFAULT_SECRETS_FILE = Path(".client.secrets.yaml")
DEFAULT_ADMIN_CLIENT_ID = "celine-admin-cli"


def _load_secret_from_file(
    secrets_file: Path = DEFAULT_SECRETS_FILE,
    client_id: str = DEFAULT_ADMIN_CLIENT_ID,
) -> str | None:
    """Try to load client secret from .client.secrets.yaml.

    Returns the secret if found, None otherwise.
    """
    if not secrets_file.exists():
        return None

    try:
        data = yaml.safe_load(secrets_file.read_text())
        if not isinstance(data, dict):
            return None

        clients = data.get("clients", {})
        if not isinstance(clients, dict):
            return None

        client_data = clients.get(client_id, {})
        if isinstance(client_data, dict):
            secret = client_data.get("secret")
            if secret:
                logger.debug("Loaded secret for %s from %s", client_id, secrets_file)
                return str(secret)
    except Exception as e:
        logger.debug("Failed to load secrets file %s: %s", secrets_file, e)

    return None


class KeycloakSettings(BaseSettings):
    """Keycloak connection and authentication settings."""

    model_config = SettingsConfigDict(
        env_prefix="CELINE_KEYCLOAK_",
        extra="ignore",
    )

    # Connection
    base_url: str = Field(
        default="http://keycloak.celine.localhost",
        description="Keycloak base URL",
    )
    realm: str = Field(
        default="celine",
        description="Target realm name",
    )
    timeout: float = Field(
        default=30.0,
        description="HTTP request timeout in seconds",
    )

    # Admin user authentication (for bootstrap)
    admin_user: str | None = Field(
        default=None,
        description="Keycloak admin username (for bootstrap)",
    )
    admin_password: str | None = Field(
        default=None,
        description="Keycloak admin password (for bootstrap)",
    )

    # Secrets file for auto-loading/saving client credentials
    secrets_file: Path = Field(
        default=DEFAULT_SECRETS_FILE,
        description="Path to secrets file for auto-loading client credentials",
    )

    # Service client authentication (preferred for operations)
    admin_client_id: str = Field(
        default=DEFAULT_ADMIN_CLIENT_ID,
        description="Admin service client ID",
    )
    admin_client_secret: str | None = Field(
        default=None,
        description="Admin service client secret",
    )

    @property
    def realm_url(self) -> str:
        """Get the realm-specific URL."""
        return f"{self.base_url.rstrip('/')}/realms/{self.realm}"

    @property
    def admin_url(self) -> str:
        """Get the admin API URL for the realm."""
        return f"{self.base_url.rstrip('/')}/admin/realms/{self.realm}"

    @property
    def master_realm_url(self) -> str:
        """Get the master realm URL (for admin token)."""
        return f"{self.base_url.rstrip('/')}/realms/master"

    @property
    def has_client_credentials(self) -> bool:
        """Check if service client credentials are available."""
        return bool(self.admin_client_id and self.admin_client_secret)

    @property
    def has_admin_credentials(self) -> bool:
        """Check if admin user credentials are available."""
        return bool(self.admin_user and self.admin_password)

    def with_overrides(
        self,
        *,
        base_url: str | None = None,
        realm: str | None = None,
        admin_user: str | None = None,
        admin_password: str | None = None,
        admin_client_id: str | None = None,
        admin_client_secret: str | None = None,
        secrets_file: Path | None = None,
    ) -> "KeycloakSettings":
        """Create a new settings instance with CLI overrides applied."""
        return KeycloakSettings(
            base_url=base_url or self.base_url,
            realm=realm or self.realm,
            timeout=self.timeout,
            admin_user=admin_user or self.admin_user,
            admin_password=admin_password or self.admin_password,
            admin_client_id=admin_client_id or self.admin_client_id,
            admin_client_secret=admin_client_secret or self.admin_client_secret,
            secrets_file=secrets_file or self.secrets_file,
        )

    def with_auto_secret(
        self,
        secrets_file: Path | None = None,
    ) -> "KeycloakSettings":
        """Try to auto-load secret from the secrets file if not already set.

        Uses self.secrets_file (from env CELINE_KEYCLOAK_SECRETS_FILE or
        default) unless explicitly overridden.
        Only loads for the default admin client (celine-admin-cli).
        """
        if self.admin_client_secret:
            return self

        if self.admin_client_id != DEFAULT_ADMIN_CLIENT_ID:
            return self

        path = secrets_file or self.secrets_file
        secret = _load_secret_from_file(path, self.admin_client_id)
        if secret:
            logger.info("Auto-loaded credentials from %s", path)
            return self.with_overrides(admin_client_secret=secret)

        return self


class SyncUsersSettings(BaseSettings):  # <<< NEW
    """Settings for the sync-users command.

    All fields read from env vars under the CELINE_SYNC_USERS_* prefix.
    CLI flags override these values via with_overrides().

    Environment variables:
        CELINE_SYNC_USERS_REC_YAML          Path to REC registry YAML
        CELINE_SYNC_USERS_GROUPS            Space-separated group paths
                                            default: /viewers
        CELINE_SYNC_USERS_TEMP_PASSWORD     Fixed temp password for all users.
                                            Unset → random password per user.
        CELINE_SYNC_USERS_DRY_RUN           "true" / "1" to enable dry-run
        CELINE_SYNC_USERS_VERBOSE           "true" / "1" to enable verbose
    """

    model_config = SettingsConfigDict(
        env_prefix="CELINE_SYNC_USERS_",
        extra="ignore",
    )

    rec_yaml: Path | None = Field(
        default=None,
        description="Path to REC registry YAML file",
    )
    groups: list[str] = Field(
        default=[],
        description="Group paths to assign to every created user (derived from community type if empty)",
    )
    temp_password: str | None = Field(
        default=None,
        description="Fixed temporary password. None → random per user.",
    )
    temporary: bool = Field(
        default=True,
        description="Whether passwords are temporary (forced reset on first login)",
    )
    dry_run: bool = Field(
        default=False,
        description="Show planned changes without applying them",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose / debug output",
    )

    def with_overrides(
        self,
        *,
        rec_yaml: Path | None = None,
        groups: list[str] | None = None,
        temp_password: str | None = None,
        temporary: bool | None = None,
        dry_run: bool | None = None,
        verbose: bool | None = None,
    ) -> "SyncUsersSettings":
        """Return a new instance with any provided CLI overrides applied."""
        return SyncUsersSettings(
            rec_yaml=rec_yaml if rec_yaml is not None else self.rec_yaml,
            groups=groups if groups is not None else self.groups,
            temp_password=(
                temp_password if temp_password is not None else self.temp_password
            ),
            temporary=temporary if temporary is not None else self.temporary,
            dry_run=dry_run if dry_run is not None else self.dry_run,
            verbose=verbose if verbose is not None else self.verbose,
        )

    def generate_password(self) -> str:
        """Return the configured temp password, or generate a random one."""
        if self.temp_password:
            return self.temp_password
        alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$"
        return "".join(_secrets.choice(alphabet) for _ in range(16))
