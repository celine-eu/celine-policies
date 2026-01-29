from fastapi import APIRouter, Depends

from celine.policies.models import AuthorizationDecision
from celine.policies.routes.deps import get_audit_logger, get_engine, get_subject

router = APIRouter(prefix="/pipelines", tags=["pipelines"])


@router.get("/{pipeline_id}/authorize", response_model=AuthorizationDecision)
async def authorize_pipeline(
    pipeline_id: str,
    subject=Depends(get_subject),
    engine=Depends(get_engine),
    audit_logger=Depends(get_audit_logger),
):
    decision = engine.evaluate(
        subject=subject,
        action="execute",
        resource={"type": "pipeline", "id": pipeline_id},
        context={},
    )

    audit_logger.log_authorization(
        subject=subject,
        action="execute",
        resource={"type": "pipeline", "id": pipeline_id},
        decision=decision,
        context={},
    )

    return decision
