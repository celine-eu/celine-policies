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
from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

import secrets as _secrets

logger = logging.getLogger(__name__)

# Default secrets file path
DEFAULT_SECRETS_FILE = Path(".client.secrets.yaml")
#: The client `bootstrap` creates for the operator CLI. It holds
#: `REQUIRED_REALM_MGMT_ROLES` — realm-wide client, realm and user administration
#: — and it is **not declared in `clients.yaml`**, because `sync` runs *as* it.
#: That combination is why it needs naming rather than repeating: a client the
#: declaration does not mention is an orphan, and pruning this one deletes the
#: credential the pruning run is authenticated with.
DEFAULT_ADMIN_CLIENT_ID = "celine-admin-cli"

# Values of ENV that mean "the clients.yaml fallbacks are what I want".
# Everything else — including a typo and including nothing at all — is treated
# as production, so the safety checks are on unless someone opted out on purpose.
NON_PRODUCTION_ENVS = frozenset({"dev", "development", "local", "test", "ci"})


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
        # `env` declares explicit aliases, which would otherwise be the only way
        # to set it — this keeps KeycloakSettings(env="dev") working too.
        populate_by_name=True,
    )

    # Deployment environment. Defaults to production so that a deployment which
    # says nothing gets the strict checks; dev opts out explicitly (taskfile.yaml
    # exports ENV=dev, where the clients.yaml secret fallbacks are the point).
    #
    # Read from CELINE_KEYCLOAK_ENV, CELINE_ENV or plain ENV, in that order. The
    # bare name is accepted because it is the conventional one in deployment
    # manifests — but it is also a POSIX shell variable in some setups, so a
    # prefixed name wins when both are present.
    env: str = Field(
        default="prod",
        validation_alias=AliasChoices("CELINE_KEYCLOAK_ENV", "CELINE_ENV", "ENV"),
        description="Deployment environment: 'prod' (default, strict) or 'dev'",
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

    # Platform activation (bootstrap). Unset means the environment decides; see
    # `brute_force_protected`.
    brute_force_enabled: bool | None = Field(
        default=None,
        description="Realm brute-force protection: on unless ENV is non-production",
    )

    @property
    def brute_force_protected(self) -> bool:
        """`bruteForceProtected` for this run (requester, 2026-09-14).

        On by default and off in dev: a deployment that says nothing is protected,
        and a developer locking themselves out of a local realm is not a feature.
        `CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED` overrides either way.
        """
        if self.brute_force_enabled is not None:
            return self.brute_force_enabled
        return self.is_production

    @property
    def is_production(self) -> bool:
        """Whether to apply production safety checks.

        True unless ENV names a known non-production environment. An unset or
        misspelled value is production: the failure mode of being strict in dev
        is a one-line export, the other way round it is a guessable secret in a
        live realm.
        """
        return self.env.strip().lower() not in NON_PRODUCTION_ENVS

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
            env=self.env,
            brute_force_enabled=self.brute_force_enabled,
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


def realm_is_set_in_environment() -> bool:
    """Whether the environment aims the realm, rather than leaving it defaulted.

    `KeycloakSettings().realm` cannot answer this: an unset variable and one set
    to the default value read identically. Pydantic records which fields a source
    actually supplied, so ask it rather than reading `os.environ` by hand — the
    answer stays right if the alias changes or a settings source is added.

    `sync` is the only caller: it is the one command with a third input for the
    realm (`realm:` in clients.yaml), and it has to know whether that input is
    filling a gap or overruling a deliberate choice.
    """
    return "realm" in KeycloakSettings().model_fields_set


class SmtpSettings(BaseSettings):
    """The realm's `smtpServer`, as `keycloak bootstrap` applies it (plan Phase 2b).

    Read from the environment only: the deployment feeds these from its secret, and
    `platform.yaml` refuses `smtpServer`. Names mirror Keycloak's own keys:

        CELINE_KEYCLOAK_SMTP_HOST               unset or empty: bootstrap leaves smtpServer alone
        CELINE_KEYCLOAK_SMTP_PORT               default 587
        CELINE_KEYCLOAK_SMTP_FROM               required with a host
        CELINE_KEYCLOAK_SMTP_FROM_DISPLAY_NAME
        CELINE_KEYCLOAK_SMTP_REPLY_TO
        CELINE_KEYCLOAK_SMTP_SSL                default false
        CELINE_KEYCLOAK_SMTP_STARTTLS           default false
        CELINE_KEYCLOAK_SMTP_AUTH               default: true when a user is set
        CELINE_KEYCLOAK_SMTP_USER
        CELINE_KEYCLOAK_SMTP_PASSWORD           write-only; sent on every run

    The password is a `SecretStr`, so it stays out of reprs and logs.
    """

    model_config = SettingsConfigDict(env_prefix="CELINE_KEYCLOAK_SMTP_", extra="ignore")

    host: str = ""
    port: int = 587
    from_: str = Field(default="", validation_alias=AliasChoices("CELINE_KEYCLOAK_SMTP_FROM", "from_"))
    from_display_name: str = ""
    reply_to: str = ""
    ssl: bool = False
    starttls: bool = False
    auth: bool | None = None
    user: str = ""
    password: SecretStr = SecretStr("")

    @property
    def configured(self) -> bool:
        return bool(self.host.strip())

    @property
    def uses_auth(self) -> bool:
        return self.auth if self.auth is not None else bool(self.user)


class SyncUsersSettings(BaseSettings):  # <<< NEW
    """Settings for the sync-users command.

    All fields read from env vars under the CELINE_SYNC_USERS_* prefix.
    CLI flags override these values via with_overrides().

    Environment variables:
        CELINE_SYNC_USERS_REC_YAML          Path to REC registry YAML
        CELINE_SYNC_USERS_GROUPS            Space-separated realm group paths
                                            to also assign, e.g. /admins.
                                            default: none (org-level only)
        CELINE_SYNC_USERS_TEMP_PASSWORD     Fixed temp password for all users.
                                            Unset → random password per user.
        CELINE_SYNC_USERS_DRY_RUN           "true" / "1" to enable dry-run
        CELINE_SYNC_USERS_VERBOSE           "true" / "1" to enable verbose

    Reading the live registry instead of a file:
        CELINE_SYNC_USERS_REGISTRY_URL      rec-registry base URL. Setting it is
                                            what selects the registry source.
        CELINE_SYNC_USERS_REGISTRY_CLIENT_ID
                                            Keycloak client to read it as.
                                            default: celine-cli
        CELINE_SYNC_USERS_REGISTRY_CLIENT_SECRET
                                            Its secret. Falls back to the entry
                                            for that client in the secrets file.
        CELINE_SYNC_USERS_COMMUNITIES       Space-separated community keys.
                                            Unset → every community.
    """

    model_config = SettingsConfigDict(
        env_prefix="CELINE_SYNC_USERS_",
        extra="ignore",
    )

    rec_yaml: Path | None = Field(
        default=None,
        description="Path to REC registry YAML file",
    )
    registry_url: str | None = Field(
        default=None,
        description="rec-registry base URL; set to read the live registry",
    )
    registry_client_id: str = Field(
        default="celine-cli",
        description="Keycloak client used to authenticate to rec-registry",
    )
    registry_client_secret: str | None = Field(
        default=None,
        description="Secret for the registry client; falls back to the secrets file",
    )
    communities: list[str] = Field(
        default=[],
        description="Community keys to reconcile. Empty → every community.",
    )
    groups: list[str] = Field(
        default=[],
        description="Realm group paths to also assign every participant. Empty → none; the org-level group is assigned regardless.",
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
        registry_url: str | None = None,
        registry_client_id: str | None = None,
        registry_client_secret: str | None = None,
        communities: list[str] | None = None,
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
            registry_url=(
                registry_url if registry_url is not None else self.registry_url
            ),
            registry_client_id=(
                registry_client_id
                if registry_client_id is not None
                else self.registry_client_id
            ),
            registry_client_secret=(
                registry_client_secret
                if registry_client_secret is not None
                else self.registry_client_secret
            ),
            communities=communities if communities is not None else self.communities,
        )

    def resolve_registry_secret(self, secrets_file: Path) -> str | None:
        """The registry client's secret, from the flag, the env or the store.

        The secrets file is the last of the three because it is the least
        explicit, and it is consulted at all because `sync` writes every client
        it created or updated there — so on a realm this CLI provisioned, the
        credential is usually already on disk.

        **It is not always there.** `write_secrets_file` records only the
        clients a given run touched, so a realm whose `celine-cli` was synced
        long ago has an entry for it and one synced before that convention does
        not. Returning None here is therefore ordinary, and the caller's refusal
        has to name all three inputs rather than only this one.
        """
        if self.registry_client_secret:
            return self.registry_client_secret
        return _load_secret_from_file(secrets_file, self.registry_client_id)

    def generate_password(self) -> str:
        """Return the configured temp password, or generate a random one."""
        if self.temp_password:
            return self.temp_password
        alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$"
        return "".join(_secrets.choice(alphabet) for _ in range(16))
