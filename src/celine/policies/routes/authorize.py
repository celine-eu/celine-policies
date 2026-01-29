"""Generic authorization endpoint."""

import time
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, status

from ..auth import JWTValidationError, extract_subject_from_claims
from ..models import (
    Action,
    AuthorizeRequest,
    AuthorizeResponse,
    Decision,
    PolicyInput,
    Resource,
    Subject,
)

router = APIRouter(tags=["authorization"])


def get_engine():
    """Dependency to get policy engine."""
    from ..main import get_policy_engine
    return get_policy_engine()


def get_jwt_validator():
    """Dependency to get JWT validator."""
    from ..main import get_jwt_validator
    return get_jwt_validator()


def get_audit_logger():
    """Dependency to get audit logger."""
    from ..main import get_audit_logger
    return get_audit_logger()


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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/authorize", response_model=AuthorizeResponse)
async def authorize(
    request: AuthorizeRequest,
    subject: Annotated[Subject | None, Depends(get_subject)],
    engine=Depends(get_engine),
    audit=Depends(get_audit_logger),
    x_request_id: Annotated[str | None, Header()] = None,
    x_source_service: Annotated[str | None, Header()] = None,
) -> AuthorizeResponse:
    """Generic authorization endpoint.
    
    Evaluates the appropriate policy based on resource type.
    """
    request_id = x_request_id or str(uuid.uuid4())
    start_time = time.perf_counter()
    
    # Build policy input
    policy_input = PolicyInput(
        subject=subject,
        resource=request.resource,
        action=request.action,
        environment={
            "request_id": request_id,
            "timestamp": time.time(),
            **request.context,
        },
    )
    
    # Determine policy package based on resource type
    policy_package = _get_policy_package(request.resource)
    
    try:
        # Evaluate policy
        decision, cached = engine.evaluate_decision(policy_package, policy_input)
        
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        # Audit log
        audit.log_decision(
            request_id=request_id,
            decision=decision,
            policy_input=policy_input,
            latency_ms=latency_ms,
            cached=cached,
            source_service=x_source_service,
        )
        
        return AuthorizeResponse(
            allowed=decision.allowed,
            reason=decision.reason,
            request_id=request_id,
        )
        
    except Exception as e:
        latency_ms = (time.perf_counter() - start_time) * 1000
        audit.log_error(
            request_id=request_id,
            error=str(e),
            policy_input=policy_input,
            source_service=x_source_service,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {e}",
        )


def _get_policy_package(resource: Resource) -> str:
    """Map resource type to policy package."""
    mapping = {
        "dataset": "celine.dataset.access",
        "pipeline": "celine.pipeline.state",
        "twin": "celine.twin.access",
        "topic": "celine.mqtt.acl",
        "userdata": "celine.userdata.access",
    }
    
    resource_type = resource.type.value if hasattr(resource.type, "value") else str(resource.type)
    
    if resource_type not in mapping:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown resource type: {resource_type}",
        )
    
    return mapping[resource_type]
