from fastapi import APIRouter, Depends

from celine.policies.routes.deps import get_engine

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health(engine=Depends(get_engine)):
    return {
        "status": "ok",
        "policies_loaded": engine.policy_count,
        "data_loaded": engine.data_count,
    }
