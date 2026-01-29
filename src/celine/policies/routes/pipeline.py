"""Pipeline authorization endpoints."""

import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from ..models import (
    Action,
    PipelineTransitionRequest,
    PipelineTransitionResponse,
    PolicyInput,
    Resource,
    ResourceType,
    Subject,
)
from .authorize import get_audit_logger, get_engine, get_subject

router = APIRouter(prefix="/pipeline", tags=["pipeline"])


@router.post("/transition", response_model=PipelineTransitionResponse)
async def check_pipeline_transition(
    request: PipelineTransitionRequest,
    subject: Annotated[Subject | None, Depends(get_subject)],
    engine=Depends(get_engine),
    audit=Depends(get_audit_logger),
    x_request_id: Annotated[str | None, Header()] = None,
    x_source_service: Annotated[str | None, Header()] = None,
) -> PipelineTransitionResponse:
    """Check if subject can perform a pipeline state transition."""
    request_id = x_request_id or str(uuid.uuid4())
    start_time = time.perf_counter()
    
    if subject is None:
        return PipelineTransitionResponse(
            allowed=False,
            reason="authentication required",
            request_id=request_id,
        )
    
    # Build policy input
    policy_input = PolicyInput(
        subject=subject,
        resource=Resource(
            type=ResourceType.PIPELINE,
            id=request.pipeline_id,
            attributes={},
        ),
        action=Action(
            name="transition",
            context={
                "from_state": request.from_state,
                "to_state": request.to_state,
            },
        ),
        environment={"request_id": request_id, "timestamp": time.time()},
    )
    
    try:
        decision, cached = engine.evaluate_decision("celine.pipeline.state", policy_input)
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        audit.log_decision(
            request_id=request_id,
            decision=decision,
            policy_input=policy_input,
            latency_ms=latency_ms,
            cached=cached,
            source_service=x_source_service,
        )
        
        return PipelineTransitionResponse(
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


@router.get("/states")
async def get_valid_states() -> dict:
    """Get all valid pipeline states and transitions."""
    return {
        "states": ["pending", "started", "running", "completed", "failed", "cancelled"],
        "transitions": {
            "pending": ["started", "cancelled"],
            "started": ["running", "failed", "cancelled"],
            "running": ["completed", "failed", "cancelled"],
            "completed": [],
            "failed": ["pending"],
            "cancelled": ["pending"],
        },
    }
