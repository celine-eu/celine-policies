"""Generic authorization endpoint."""

import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from celine.policies.api import PolicyAPI, PolicyPackageError
from celine.policies.models import AuthorizeRequest, AuthorizeResponse, PolicyInput, Subject
from celine.policies.routes.deps import get_policy_api, get_subject

router = APIRouter(tags=["authorization"])


@router.post("/authorize", response_model=AuthorizeResponse)
async def authorize(
    request: AuthorizeRequest,
    subject: Annotated[Subject | None, Depends(get_subject)],
    api: PolicyAPI = Depends(get_policy_api),
    x_request_id: Annotated[str | None, Header()] = None,
    x_source_service: Annotated[str | None, Header()] = None,
) -> AuthorizeResponse:
    request_id = x_request_id or str(uuid.uuid4())

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
        result = api.evaluate_for_resource(
            request_id=request_id,
            policy_input=policy_input,
            source_service=x_source_service,
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {e}",
        )
