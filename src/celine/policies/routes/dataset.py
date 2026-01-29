from fastapi import APIRouter, Depends

from celine.policies.models import AuthorizationDecision
from celine.policies.routes.deps import get_audit_logger, get_engine, get_subject

router = APIRouter(prefix="/datasets", tags=["datasets"])


@router.get("/{dataset_id}/authorize", response_model=AuthorizationDecision)
async def authorize_dataset(
    dataset_id: str,
    subject=Depends(get_subject),
    engine=Depends(get_engine),
    audit_logger=Depends(get_audit_logger),
):
    decision = engine.evaluate(
        subject=subject,
        action="read",
        resource={"type": "dataset", "id": dataset_id},
        context={},
    )

    audit_logger.log_authorization(
        subject=subject,
        action="read",
        resource={"type": "dataset", "id": dataset_id},
        decision=decision,
        context={},
    )

    return decision
