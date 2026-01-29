"""MQTT authorization endpoints (mosquitto-go-auth compatible)."""

import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response, status

from celine.policies.routes.deps import get_audit_logger, get_policy_engine, get_jwt_validator

from celine.policies.auth import JWTValidationError, extract_subject_from_claims
from celine.policies.models import (
    Action,
    MqttAclRequest,
    MqttAuthRequest,
    MqttResponse,
    MqttSuperuserRequest,
    PolicyInput,
    Resource,
    ResourceType,
    Subject,
    SubjectType,
)
from celine.policies.routes.deps import get_audit_logger, get_policy_engine, get_jwt_validator

router = APIRouter(prefix="/mqtt", tags=["mqtt"])


def _extract_subject_from_username(
    username: str,
    jwt_validator,
) -> Subject | None:
    """Extract subject from MQTT username.
    
    The username may contain:
    1. A JWT token directly
    2. A username that maps to a known service
    3. A regular username (for password auth - not supported here)
    """
    # Try to parse as JWT
    if username.count(".") == 2:  # JWT has 3 parts
        try:
            claims = jwt_validator.validate(username)
            return extract_subject_from_claims(claims)
        except JWTValidationError:
            pass  # Not a valid JWT, continue
    
    # Could add service account mapping here
    # For now, return None for non-JWT usernames
    return None


@router.post("/auth")
async def mqtt_auth(
    request: MqttAuthRequest,
    response: Response,
    jwt_validator=Depends(get_jwt_validator),
    audit=Depends(get_audit_logger),
    x_request_id: Annotated[str | None, Header()] = None,
) -> MqttResponse:
    """MQTT user authentication endpoint.
    
    mosquitto-go-auth expects:
    - HTTP 200 for authentication success
    - HTTP 401/403 for authentication failure
    
    We validate the JWT token passed in the username field.
    """
    request_id = x_request_id or str(uuid.uuid4())
    
    subject = _extract_subject_from_username(request.username, jwt_validator)
    
    if subject is None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")
    
    # Authentication successful
    return MqttResponse(ok=True, reason="authenticated")


@router.post("/acl")
async def mqtt_acl(
    request: MqttAclRequest,
    response: Response,
    engine=Depends(get_policy_engine),
    jwt_validator=Depends(get_jwt_validator),
    audit=Depends(get_audit_logger),
    x_request_id: Annotated[str | None, Header()] = None,
) -> MqttResponse:
    """MQTT ACL check endpoint.
    
    mosquitto-go-auth calls this for every publish/subscribe action.
    
    acc values:
    - 1 = subscribe
    - 2 = publish  
    - 3 = subscribe + publish
    - 4 = subscribe (literal, no wildcards)
    """
    request_id = x_request_id or str(uuid.uuid4())
    start_time = time.perf_counter()
    
    # Extract subject from username (JWT)
    subject = _extract_subject_from_username(request.username, jwt_validator)
    
    if subject is None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")
    
    # Map acc to action
    action_name = _acc_to_action(request.acc)
    
    # Build policy input
    policy_input = PolicyInput(
        subject=subject,
        resource=Resource(
            type=ResourceType.TOPIC,
            id=request.topic,
            attributes={"clientid": request.clientid},
        ),
        action=Action(name=action_name, context={"acc": request.acc}),
        environment={"request_id": request_id, "timestamp": time.time()},
    )
    
    try:
        decision, cached = engine.evaluate_decision("celine.mqtt.acl", policy_input)
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        audit.log_decision(
            request_id=request_id,
            decision=decision,
            policy_input=policy_input,
            latency_ms=latency_ms,
            cached=cached,
            source_service="mosquitto",
        )
        
        if not decision.allowed:
            response.status_code = status.HTTP_403_FORBIDDEN
            
        return MqttResponse(ok=decision.allowed, reason=decision.reason)
        
    except Exception as e:
        audit.log_error(request_id=request_id, error=str(e), policy_input=policy_input)
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return MqttResponse(ok=False, reason=f"policy error: {e}")


@router.post("/superuser")
async def mqtt_superuser(
    request: MqttSuperuserRequest,
    response: Response,
    engine=Depends(get_policy_engine),
    jwt_validator=Depends(get_jwt_validator),
    x_request_id: Annotated[str | None, Header()] = None,
) -> MqttResponse:
    """MQTT superuser check endpoint.
    
    Superusers bypass all ACL checks.
    """
    request_id = x_request_id or str(uuid.uuid4())
    
    subject = _extract_subject_from_username(request.username, jwt_validator)
    
    if subject is None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")
    
    # Build minimal input for superuser check
    policy_input = PolicyInput(
        subject=subject,
        resource=Resource(
            type=ResourceType.TOPIC,
            id="*",  # Superuser check is not topic-specific
            attributes={},
        ),
        action=Action(name="superuser", context={}),
        environment={"request_id": request_id},
    )
    
    try:
        # Evaluate superuser rule directly
        result = engine.evaluate("data.celine.mqtt.acl.superuser", engine._build_input(policy_input))
        is_superuser = bool(result.get("value", False))
        
        if not is_superuser:
            response.status_code = status.HTTP_403_FORBIDDEN
            
        return MqttResponse(ok=is_superuser, reason="superuser" if is_superuser else "not superuser")
        
    except Exception as e:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason=f"check failed: {e}")


def _acc_to_action(acc: int) -> str:
    """Map mosquitto-go-auth acc value to action name."""
    if acc == 1 or acc == 4:
        return "subscribe"
    elif acc == 2:
        return "publish"
    elif acc == 3:
        return "subscribe"  # Check subscribe first, publish separately if needed
    else:
        return "unknown"

