"""Configuration for MQTT auth service."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from celine.sdk.settings.models import OidcSettings


class MqttAuthSettings(BaseSettings):
    """MQTT Auth service settings.

    Inherits OIDC and policy settings from environment variables.
    """

    model_config = SettingsConfigDict(env_prefix="CELINE_", extra="ignore")

    oidc: OidcSettings = OidcSettings(audience=None)

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
