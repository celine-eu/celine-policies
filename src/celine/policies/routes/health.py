"""Health check endpoints."""

from typing import Any

from fastapi import APIRouter, Depends

from ..models import HealthResponse

router = APIRouter(tags=["health"])


def get_engine():
    """Dependency to get policy engine - injected at app startup."""
    from ..main import get_policy_engine
    return get_policy_engine()


@router.get("/health", response_model=HealthResponse)
async def health_check(engine=Depends(get_engine)) -> HealthResponse:
    """Liveness check - is the service running?"""
    return HealthResponse(
        status="healthy" if engine.is_loaded else "unhealthy",
        version="0.1.0",
        policies_loaded=engine.is_loaded,
        details={
            "policy_count": engine.policy_count,
        },
    )


@router.get("/ready", response_model=HealthResponse)
async def readiness_check(engine=Depends(get_engine)) -> HealthResponse:
    """Readiness check - is the service ready to accept requests?"""
    is_ready = engine.is_loaded and engine.policy_count > 0
    
    details: dict[str, Any] = {
        "policy_count": engine.policy_count,
    }
    
    # Add cache stats if available
    if hasattr(engine, "cache_stats"):
        details["cache"] = engine.cache_stats
    
    return HealthResponse(
        status="healthy" if is_ready else "unhealthy",
        version="0.1.0",
        policies_loaded=engine.is_loaded,
        details=details,
    )


@router.post("/reload")
async def reload_policies(engine=Depends(get_engine)) -> dict[str, Any]:
    """Reload policies from disk (admin endpoint)."""
    try:
        engine.reload()
        return {
            "status": "success",
            "policy_count": engine.policy_count,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
        }
