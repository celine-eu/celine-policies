from fastapi import APIRouter, Depends

from celine.policies.models import AuthorizationDecision
from celine.policies.routes.deps import get_audit_logger, get_engine, get_jwt_validator

router = APIRouter(prefix="/mqtt", tags=["mqtt"])


@router.get("/authorize", response_model=AuthorizationDecision)
async def authorize_mqtt(
    client_id: str,
    topic: str,
    action: str,
    engine=Depends(get_engine),
    audit_logger=Depends(get_audit_logger),
    jwt_validator=Depends(get_jwt_validator),
):
    subject = jwt_validator.validate_client_credentials(client_id)

    decision = engine.evaluate(
        subject=subject,
        action=action,
        resource={"type": "mqtt", "topic": topic},
        context={},
    )

    audit_logger.log_authorization(
        subject=subject,
        action=action,
        resource={"type": "mqtt", "topic": topic},
        decision=decision,
        context={},
    )

    return decision
