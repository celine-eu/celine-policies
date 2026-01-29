from fastapi import APIRouter, Depends

from celine.policies.models import AuthorizationDecision, AuthorizationRequest
from celine.policies.routes.deps import get_audit_logger, get_engine, get_subject

router = APIRouter(prefix="/authorize", tags=["authorize"])


@router.post("", response_model=AuthorizationDecision)
async def authorize(
    request: AuthorizationRequest,
    subject=Depends(get_subject),
    engine=Depends(get_engine),
    audit_logger=Depends(get_audit_logger),
):
    decision = engine.evaluate(
        subject=subject,
        action=request.action,
        resource=request.resource,
        context=request.context,
    )

    audit_logger.log_authorization(
        subject=subject,
        action=request.action,
        resource=request.resource,
        decision=decision,
        context=request.context,
    )

    return decision
