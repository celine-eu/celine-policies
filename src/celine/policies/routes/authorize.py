"""Unified authorization endpoint with policy routing.

Routes to specialized policies based on resource.type:
  - dataset → celine.dataset (if exists)
  - dt      → celine.dt (if exists) → fallback to celine.authz
  - *       → celine.authz (generic fallback)
"""

import logging
import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from celine.policies.api import PolicyAPI, PolicyPackageError
from celine.policies.engine import PolicyEngine
from celine.policies.models import (
    AuthorizeRequest,
    AuthorizeResponse,
    PolicyInput,
    Subject,
)
from celine.policies.routes.deps import get_policy_api, get_policy_engine, get_subject

logger = logging.getLogger(__name__)

router = APIRouter(tags=["authorization"])

# Fallback policy when no specialized policy exists
FALLBACK_POLICY = "celine.authz"


def resolve_policy_package(engine: PolicyEngine, resource_type: str) -> str:
    """Resolve policy package for a resource type.

    Tries specialized policy first (celine.{resource_type}),
    falls back to generic policy (celine.authz) if not found.

    Args:
        engine: Policy engine with loaded packages
        resource_type: Resource type from request (e.g., "dataset", "dt")

    Returns:
        Policy package name to evaluate
    """
    specific_package = f"celine.{resource_type}"

    if engine.has_package(specific_package):
        logger.debug("Using specialized policy: %s", specific_package)
        return specific_package

    logger.debug(
        "No specialized policy for '%s', using fallback: %s",
        resource_type,
        FALLBACK_POLICY,
    )
    return FALLBACK_POLICY


@router.post("/authorize", response_model=AuthorizeResponse)
async def authorize(
    request: AuthorizeRequest,
    subject: Annotated[Subject | None, Depends(get_subject)],
    api: PolicyAPI = Depends(get_policy_api),
    engine: PolicyEngine = Depends(get_policy_engine),
    x_request_id: Annotated[str | None, Header()] = None,
    x_source_service: Annotated[str | None, Header()] = None,
) -> AuthorizeResponse:
    """Authorize a resource action.

    Policy routing:
    - Specialized policies are tried first (celine.{resource.type})
    - Falls back to generic policy (celine.authz) if not found

    Scope derivation (in generic policy):
        {resource.type}.{resource.attributes.resource_type}.{action.name}

    Examples:
        - type=dataset → celine.dataset (specialized, has access_level logic)
        - type=dt, resource_type=simulation, action=read → celine.authz → dt.simulation.read
        - type=pipeline, resource_type=status, action=write → celine.authz → pipeline.status.write
    """
    request_id = x_request_id or str(uuid.uuid4())

    # Resolve policy package based on resource type
    resource_type = request.resource.type.value
    policy_package = resolve_policy_package(engine, resource_type)

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

    try:
        result = api.evaluate(
            request_id=request_id,
            policy_package=policy_package,
            policy_input=policy_input,
            source_service=x_source_service,
        )

        logger.debug(
            "Authorization result: resource_type=%s policy=%s allowed=%s reason=%s",
            resource_type,
            policy_package,
            result.decision.allowed,
            result.decision.reason,
        )

        return AuthorizeResponse(
            allowed=result.decision.allowed,
            reason=result.decision.reason,
            request_id=request_id,
        )
    except PolicyPackageError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.exception("Policy evaluation failed", exc_info=e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {e}",
        )


@router.get("/policies")
async def list_policies(
    engine: PolicyEngine = Depends(get_policy_engine),
) -> dict:
    """List loaded policy packages (debug/admin endpoint)."""
    return {
        "packages": engine.get_packages(),
        "fallback": FALLBACK_POLICY,
    }
