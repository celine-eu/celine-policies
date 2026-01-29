"""Application configuration using pydantic-settings."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="CELINE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Service
    service_name: str = "celine-policies"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Policies
    policies_dir: Path = Field(default=Path("policies"))
    data_dir: Path = Field(default=Path("data"))

    # JWT / OIDC
    oidc_issuer: str = "http://keycloak.celine.localhost/realms/celine"
    oidc_jwks_uri: str | None = None  # Auto-derived from issuer if not set
    oidc_audience: str | None = None  # If set, validate aud claim
    jwt_algorithms: list[str] = Field(default=["RS256"])

    # Cache
    decision_cache_enabled: bool = True
    decision_cache_maxsize: int = 10000
    decision_cache_ttl_seconds: int = 300  # 5 minutes

    jwks_cache_ttl_seconds: int = 3600  # 1 hour

    # Audit
    audit_enabled: bool = True
    audit_log_decisions: bool = True
    audit_log_inputs: bool = True  # Log full inputs (disable in prod if sensitive)

    @property
    def jwks_uri(self) -> str:
        """Get JWKS URI, deriving from issuer if not explicitly set."""
        if self.oidc_jwks_uri:
            return self.oidc_jwks_uri
        return f"{self.oidc_issuer.rstrip('/')}/protocol/openid-connect/certs"


settings = Settings()


@lru_cache
def get_settings() -> Settings:
    """Backward-compatible alias for the module-level settings singleton."""
    return settings


