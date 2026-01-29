"""Dataset authorization endpoints."""

import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, status, HTTPException

from celine.policies.routes.deps import get_audit_logger, get_policy_engine, get_subject

from celine.policies.models import (
    Action,
    DatasetAccessRequest,
    DatasetAccessResponse,
    DatasetFilterRequest,
    DatasetFilterResponse,
    PolicyInput,
    Resource,
    ResourceType,
    Subject,
)
from celine.policies.routes.deps import get_audit_logger, get_policy_engine, get_subject

router = APIRouter(prefix="/dataset", tags=["dataset"])


@router.post("/access", response_model=DatasetAccessResponse)
async def check_dataset_access(
    request: DatasetAccessRequest,
    subject: Annotated[Subject | None, Depends(get_subject)],
    engine=Depends(get_policy_engine),
    audit=Depends(get_audit_logger),
    x_request_id: Annotated[str | None, Header()] = None,
    x_source_service: Annotated[str | None, Header()] = None,
) -> DatasetAccessResponse:
    """Check if subject can access a dataset."""
    request_id = x_request_id or str(uuid.uuid4())
    start_time = time.perf_counter()
    
    # Build policy input
    policy_input = PolicyInput(
        subject=subject,
        resource=Resource(
            type=ResourceType.DATASET,
            id=request.dataset_id,
            attributes={"access_level": request.access_level},
        ),
        action=Action(name=request.action, context={}),
        environment={"request_id": request_id, "timestamp": time.time()},
    )
    
    try:
        decision, cached = engine.evaluate_decision("celine.dataset.access", policy_input)
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        audit.log_decision(
            request_id=request_id,
            decision=decision,
            policy_input=policy_input,
            latency_ms=latency_ms,
            cached=cached,
            source_service=x_source_service,
        )
        
        return DatasetAccessResponse(
            allowed=decision.allowed,
            reason=decision.reason,
            request_id=request_id,
        )
        
    except Exception as e:
        audit.log_error(request_id=request_id, error=str(e), policy_input=policy_input)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {e}",
        )


@router.post("/filter", response_model=DatasetFilterResponse)
async def get_dataset_filters(
    request: DatasetFilterRequest,
    subject: Annotated[Subject | None, Depends(get_subject)],
    engine=Depends(get_policy_engine),
    audit=Depends(get_audit_logger),
    x_request_id: Annotated[str | None, Header()] = None,
    x_source_service: Annotated[str | None, Header()] = None,
) -> DatasetFilterResponse:
    """Get row-level filters for a dataset query.
    
    Returns filter predicates that should be applied to the query.
    """
    request_id = x_request_id or str(uuid.uuid4())
    start_time = time.perf_counter()
    
    # First check basic access
    policy_input = PolicyInput(
        subject=subject,
        resource=Resource(
            type=ResourceType.DATASET,
            id=request.dataset_id,
            attributes={"access_level": request.access_level},
        ),
        action=Action(name="read", context={}),
        environment={"request_id": request_id, "timestamp": time.time()},
    )
    
    try:
        # Check access first
        access_decision, _ = engine.evaluate_decision("celine.dataset.access", policy_input)
        
        if not access_decision.allowed:
            latency_ms = (time.perf_counter() - start_time) * 1000
            audit.log_decision(
                request_id=request_id,
                decision=access_decision,
                policy_input=policy_input,
                latency_ms=latency_ms,
                cached=False,
                source_service=x_source_service,
            )
            return DatasetFilterResponse(
                allowed=False,
                filters=[],
                reason=access_decision.reason,
                request_id=request_id,
            )
        
        # Get row-level filters
        filter_decision, cached = engine.evaluate_decision(
            "celine.dataset.row_filter", policy_input
        )
        
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        audit.log_decision(
            request_id=request_id,
            decision=filter_decision,
            policy_input=policy_input,
            latency_ms=latency_ms,
            cached=cached,
            source_service=x_source_service,
        )
        
        return DatasetFilterResponse(
            allowed=True,
            filters=filter_decision.filters,
            reason=filter_decision.reason,
            request_id=request_id,
        )
        
    except Exception as e:
        audit.log_error(request_id=request_id, error=str(e), policy_input=policy_input)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {e}",
        )

