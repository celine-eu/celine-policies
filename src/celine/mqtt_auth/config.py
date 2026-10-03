"""Configuration for MQTT auth service."""

from pathlib import Path

# TODO: celine.sdk.posture ships in the next celine-sdk release; raise the
# celine-sdk floor in pyproject.toml to it (and re-lock) before building an image.
from celine.sdk.posture import PostureGuard
from celine.sdk.settings.models import OidcSettings
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

SERVICE_NAME = "mqtt-auth"


class MqttAuthSettings(BaseSettings):
    """MQTT Auth service settings.

    Inherits OIDC and policy settings from environment variables.

    ``oidc`` is read from ``CELINE_OIDC_*`` when the settings are built, the
    audience included: ``CELINE_OIDC_AUDIENCE`` is the audience every token
    presented by an MQTT client must carry. It is optional only in dev (see
    :func:`check_posture`).
    """

    model_config = SettingsConfigDict(env_prefix="CELINE_", extra="ignore")

    oidc: OidcSettings = Field(default_factory=OidcSettings)

    # Policy engine settings
    policies_dir: Path = Field(
        default=Path("./policies"),
        description="Directory containing .rego policy files",
    )
    policies_data_dir: Path | None = Field(
        default=None, description="Optional directory containing policy data JSON files"
    )
    policies_cache_enabled: bool = Field(
        default=True, description="Enable in-memory decision caching"
    )
    policies_cache_ttl: int = Field(default=300, description="Cache TTL in seconds")
    policies_cache_maxsize: int = Field(
        default=10000, description="Maximum cache entries"
    )

    # MQTT-specific settings
    mqtt_policy_package: str = Field(
        default="celine.mqtt.acl", description="Policy package for MQTT ACL checks"
    )
    mqtt_superuser_scope: str = Field(
        default="mqtt.admin", description="OAuth scope required for MQTT superuser"
    )

    # Service settings
    log_level: str = Field(default="INFO", description="Logging level")


def check_posture(settings: MqttAuthSettings, env: str | None = None) -> PostureGuard:
    """Refuse to start outside dev with the SDK's local OIDC defaults or no audience.

    Without an audience any token the realm issues — for any client — would be
    accepted as an MQTT credential, so outside ``CELINE_ENV=dev`` the audience
    is required along with an explicitly configured issuer and JWKS. In dev the
    same findings are logged as one warning and startup proceeds.
    """
    guard = PostureGuard(SERVICE_NAME, env=env)
    guard.require_explicit_oidc(settings.oidc, require_audience=True)
    guard.enforce()
    return guard
