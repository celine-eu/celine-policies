"""JWT validation and JWKS fetching."""

import time
import threading
from typing import Any

import httpx
import jwt
import logging
from jwt import PyJWKClient, PyJWKClientError

logger = logging.getLogger(__name__)


class JWKSCache:
    """Thread-safe JWKS cache with automatic refresh."""

    def __init__(self, jwks_uri: str, ttl_seconds: int = 3600):
        """Initialize JWKS cache.

        Args:
            jwks_uri: URI to fetch JWKS from
            ttl_seconds: Cache TTL in seconds
        """
        self._jwks_uri = jwks_uri
        self._ttl_seconds = ttl_seconds
        self._client: PyJWKClient | None = None
        self._last_fetch: float = 0
        self._lock = threading.RLock()

    def get_signing_key(self, token: str) -> Any:
        """Get signing key for token.

        Handles cache refresh and retry on unknown kid.
        """
        with self._lock:
            self._ensure_client()
            try:
                return self._client.get_signing_key_from_jwt(token)  # type: ignore
            except PyJWKClientError as e:
                # Key might have rotated, force refresh
                logger.warning("JWKS key lookup failed, refreshing error=%s", e)
                self._refresh()
                return self._client.get_signing_key_from_jwt(token)  # type: ignore

    def _ensure_client(self) -> None:
        """Ensure client exists and is fresh."""
        now = time.time()
        if self._client is None or (now - self._last_fetch) > self._ttl_seconds:
            self._refresh()

    def _refresh(self) -> None:
        """Refresh JWKS client."""
        logger.debug("Refreshing JWKS uri=%s", self._jwks_uri)
        self._client = PyJWKClient(self._jwks_uri, cache_keys=True)
        self._last_fetch = time.time()


class JWTValidator:
    """JWT token validator."""

    def __init__(
        self,
        jwks_cache: JWKSCache,
        issuer: str,
        audience: str | None = None,
        algorithms: list[str] | None = None,
    ):
        """Initialize validator.

        Args:
            jwks_cache: JWKS cache instance
            issuer: Expected issuer (iss claim)
            audience: Expected audience (aud claim), optional
            algorithms: Allowed algorithms
        """
        self._jwks_cache = jwks_cache
        self._issuer = issuer
        self._audience = audience
        self._algorithms = algorithms or ["RS256"]

    def validate(self, token: str) -> dict[str, Any]:
        """Validate JWT and return claims.

        Args:
            token: JWT token string

        Returns:
            Decoded claims

        Raises:
            JWTValidationError: If validation fails
        """
        try:
            # Get signing key
            signing_key = self._jwks_cache.get_signing_key(token)

            # Build options
            options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "require": ["exp", "iat", "sub"],
            }

            # Audience validation is optional
            if self._audience:
                options["verify_aud"] = True
            else:
                options["verify_aud"] = False

            # Decode and validate
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self._algorithms,
                issuer=self._issuer,
                audience=self._audience,
                options=options,
            )

            logger.debug("JWT validated sub=%s client_id=%s", claims.get("sub"), claims.get("client_id"))

            return claims

        except jwt.ExpiredSignatureError:
            raise JWTValidationError("Token has expired")
        except jwt.InvalidIssuerError:
            raise JWTValidationError("Invalid issuer")
        except jwt.InvalidAudienceError:
            raise JWTValidationError("Invalid audience")
        except jwt.InvalidTokenError as e:
            raise JWTValidationError(f"Invalid token: {e}")
        except Exception as e:
            logger.error("JWT validation error error=%s", e)
            raise JWTValidationError(f"Validation failed: {e}")


class JWTValidationError(Exception):
    """JWT validation error."""

    pass
