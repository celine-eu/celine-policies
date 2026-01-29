from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from celine.policies.auth.jwt import JWTValidationError
from celine.policies.auth.subject import extract_subject_from_claims
from celine.policies.models import Subject

from celine.policies.audit import AuditLogger
from celine.policies.auth import JWTValidator
from celine.policies.engine import CachedPolicyEngine


_policy_engine: CachedPolicyEngine | None = None
_jwt_validator: JWTValidator | None = None
_audit_logger: AuditLogger | None = None


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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]

    try:
        claims = jwt_validator.validate(token)
        return extract_subject_from_claims(claims)
    except JWTValidationError as e:
        # Keep the previous behavior: invalid token => anonymous (not 401),
        # unless you want strict 401 here. The docstring says anonymous for invalid token.
        return None
