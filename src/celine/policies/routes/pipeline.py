"""Pipeline authorization endpoints."""

import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from celine.policies.api import PolicyAPI
from celine.policies.models import (
    Action,
    PipelineTransitionRequest,
    PipelineTransitionResponse,
    PolicyInput,
    Resource,
    Subject,
)
from celine.policies.models.core import ResourceType
from celine.policies.routes.deps import get_policy_api, get_subject

router = APIRouter(prefix="/pipeline", tags=["pipeline"])


@router.post("/transition", response_model=PipelineTransitionResponse)
async def check_pipeline_transition(
    request: PipelineTransitionRequest,
    subject: Annotated[Subject | None, Depends(get_subject)],
    api: PolicyAPI = Depends(get_policy_api),
    x_request_id: Annotated[str | None, Header()] = None,
    x_source_service: Annotated[str | None, Header()] = None,
) -> PipelineTransitionResponse:
    request_id = x_request_id or str(uuid.uuid4())

    policy_input = PolicyInput(
        subject=subject,
        resource=Resource(
            type=ResourceType.PIPELINE, id=request.pipeline_id, attributes={}
        ),
        action=Action(
            name="transition",
            context={"from_state": request.from_state, "to_state": request.to_state},
        ),
        environment={"request_id": request_id, "timestamp": time.time()},
    )

    try:
        result = api.evaluate(
            request_id=request_id,
            policy_package="celine.pipeline.state",
            policy_input=policy_input,
            source_service=x_source_service,
        )
        return PipelineTransitionResponse(
            allowed=result.decision.allowed,
            reason=result.decision.reason,
            request_id=request_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {e}",
        )
