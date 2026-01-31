"""Dataset authorization endpoints."""

import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from celine.policies.api import PolicyAPI
from celine.policies.models import (
    Action,
    DatasetAccessRequest,
    DatasetAccessResponse,
    DatasetFilterRequest,
    DatasetFilterResponse,
    PolicyInput,
    Resource,
    Subject,
)
from celine.policies.models.core import ResourceType
from celine.policies.routes.deps import get_policy_api, get_subject

router = APIRouter(prefix="/dataset", tags=["dataset"])


@router.post("/access", response_model=DatasetAccessResponse)
async def check_dataset_access(
    request: DatasetAccessRequest,
    subject: Annotated[Subject | None, Depends(get_subject)],
    api: PolicyAPI = Depends(get_policy_api),
    x_request_id: Annotated[str | None, Header()] = None,
    x_source_service: Annotated[str | None, Header()] = None,
) -> DatasetAccessResponse:
    request_id = x_request_id or str(uuid.uuid4())

    policy_input = PolicyInput(
        subject=subject,
        resource=Resource(
            type=ResourceType.DATASET,
            id=request.dataset_id,
            attributes={"access_level": request.access_level},
        ),
        action=Action(name=request.action),
        environment={"request_id": request_id, "timestamp": time.time()},
    )

    try:
        result = api.evaluate(
            request_id=request_id,
            policy_package="celine.dataset.access",
            policy_input=policy_input,
            source_service=x_source_service,
        )
        return DatasetAccessResponse(
            allowed=result.decision.allowed,
            reason=result.decision.reason,
            request_id=request_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {e}",
        )


@router.post("/filters", response_model=DatasetFilterResponse)
async def get_dataset_filters(
    request: DatasetFilterRequest,
    subject: Annotated[Subject | None, Depends(get_subject)],
    api: PolicyAPI = Depends(get_policy_api),
    x_request_id: Annotated[str | None, Header()] = None,
    x_source_service: Annotated[str | None, Header()] = None,
) -> DatasetFilterResponse:
    request_id = x_request_id or str(uuid.uuid4())

    policy_input = PolicyInput(
        subject=subject,
        resource=Resource(
            type=ResourceType.DATASET,
            id=request.dataset_id,
            attributes={"access_level": request.access_level},
        ),
        action=Action(name="filters"),
        environment={"request_id": request_id, "timestamp": time.time()},
    )

    try:
        result = api.evaluate(
            request_id=request_id,
            policy_package="celine.dataset.row_filter",
            policy_input=policy_input,
            source_service=x_source_service,
        )
        return DatasetFilterResponse(
            allowed=result.decision.allowed,
            filters=result.decision.filters,
            reason=result.decision.reason,
            request_id=request_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {e}",
        )
