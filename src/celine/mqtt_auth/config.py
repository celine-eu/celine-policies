"""Configuration for MQTT auth service."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class MqttAuthSettings(BaseSettings):
    """MQTT Auth service settings.
    
    Inherits OIDC and policy settings from environment variables.
    """

    model_config = SettingsConfigDict(env_prefix="CELINE_", extra="ignore")

    # OIDC settings for JWT validation
    oidc_jwks_uri: str | None = Field(
        default=None,
        description="JWKS URI for JWT signature verification"
    )
    oidc_issuer: str | None = Field(
        default=None,
        description="Expected JWT issuer"
    )
    oidc_audience: str | None = Field(
        default=None,
        description="Expected JWT audience"
    )

    # Policy engine settings
    policies_dir: Path = Field(
        default=Path("./policies"),
        description="Directory containing .rego policy files"
    )
    policies_data_dir: Path | None = Field(
        default=None,
        description="Optional directory containing policy data JSON files"
    )
    policies_cache_enabled: bool = Field(
        default=True,
        description="Enable in-memory decision caching"
    )
    policies_cache_ttl: int = Field(
        default=300,
        description="Cache TTL in seconds"
    )
    policies_cache_maxsize: int = Field(
        default=10000,
        description="Maximum cache entries"
    )

    # MQTT-specific settings
    mqtt_policy_package: str = Field(
        default="celine.mqtt.acl",
        description="Policy package for MQTT ACL checks"
    )
    mqtt_superuser_scope: str = Field(
        default="mqtt.admin",
        description="OAuth scope required for MQTT superuser"
    )

    # Service settings
    log_level: str = Field(
        default="INFO",
        description="Logging level"
    )
