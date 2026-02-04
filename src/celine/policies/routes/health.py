"""Health check endpoints."""

from typing import Any

from fastapi import APIRouter, Depends

from celine.policies.engine import PolicyEngine
from celine.policies.models import HealthResponse
from celine.policies.routes.deps import get_policy_engine

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check(engine=Depends(get_policy_engine)) -> HealthResponse:
    """Liveness check."""
    return HealthResponse(
        status="healthy" if engine.is_loaded else "unhealthy",
        version="0.2.0",
        policies_loaded=engine.is_loaded,
        details={"policy_count": engine.policy_count},
    )


@router.get("/ready", response_model=HealthResponse)
async def readiness_check(
    engine: PolicyEngine = Depends(get_policy_engine),
) -> HealthResponse:
    """Readiness check."""
    is_ready = engine.is_loaded and engine.policy_count > 0

    details: dict[str, Any] = {
        "policy_count": engine.policy_count,
        "packages": engine.get_packages(),
    }

    return HealthResponse(
        status="healthy" if is_ready else "unhealthy",
        version="0.2.0",
        policies_loaded=engine.is_loaded,
        details=details,
    )


@router.post("/reload")
async def reload_policies(
    engine: PolicyEngine = Depends(get_policy_engine),
) -> dict[str, Any]:
    """Reload policies from disk."""
    try:
        engine.reload()
        return {
            "status": "success",
            "policy_count": engine.policy_count,
            "packages": engine.get_packages(),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}
