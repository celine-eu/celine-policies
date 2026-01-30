from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from celine.policies.auth.jwt import JWTValidationError
from celine.policies.auth.subject import extract_subject_from_claims
from celine.policies.models import Subject

from celine.policies.audit import AuditLogger
from celine.policies.auth import JWKSCache, JWTValidator
from celine.policies.config import settings
from celine.policies.engine import CachedPolicyEngine, DecisionCache, PolicyEngine
from celine.policies.logs import configure_logging as configure_app_logging


_policy_engine: CachedPolicyEngine | None = None
_jwt_validator: JWTValidator | None = None
_audit_logger: AuditLogger | None = None


async def init_deps():

    global _policy_engine, _jwt_validator, _audit_logger

    engine = PolicyEngine(
        policies_dir=settings.policies_dir,
        data_dir=settings.data_dir,
    )
    engine.load()

    cache = DecisionCache(
        maxsize=settings.decision_cache_maxsize,
        ttl_seconds=settings.decision_cache_ttl_seconds,
    )
    _policy_engine = CachedPolicyEngine(
        engine=engine,
        cache=cache,
        cache_enabled=settings.decision_cache_enabled,
    )

    jwks_cache = JWKSCache(
        jwks_uri=settings.jwks_uri,
        ttl_seconds=settings.jwks_cache_ttl_seconds,
    )
    _jwt_validator = JWTValidator(
        jwks_cache=jwks_cache,
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        algorithms=settings.jwt_algorithms,
    )

    _audit_logger = AuditLogger(
        enabled=settings.audit_enabled,
        log_inputs=settings.audit_log_inputs,
    )

def get_policy_engine() -> CachedPolicyEngine:
    if _policy_engine is None:
        raise RuntimeError("Policy engine not initialized")
    return _policy_engine


def get_jwt_validator() -> JWTValidator:
    if _jwt_validator is None:
        raise RuntimeError("JWT validator not initialized")
    return _jwt_validator


def get_audit_logger() -> AuditLogger:
    if _audit_logger is None:
        raise RuntimeError("Audit logger not initialized")
    return _audit_logger


def raise_401(detail = "Unauthorized"):
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )

async def get_subject(
    authorization: Annotated[str | None, Header()] = None,
    jwt_validator=Depends(get_jwt_validator),
) -> Subject | None:
    """Extract subject from Authorization header.

    Returns None for anonymous access (no header or invalid token).
    Raises HTTPException for malformed tokens.
    """
    if not authorization:
        return None

    # Extract token from "Bearer <token>"
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise_401("Invalid authorization header format")

    token = parts[1]

    try:
        claims = jwt_validator.validate(token)
        return extract_subject_from_claims(claims)
    except JWTValidationError as e:
        raise_401()
