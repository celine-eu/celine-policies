"""MQTT authorization endpoints (mosquitto-go-auth compatible)."""

import logging
import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response, status

from celine.policies.api import PolicyAPI
from celine.policies.auth import JWTValidationError
from celine.policies.auth.subject import extract_subject_from_claims
from celine.policies.models import (
    Action,
    MqttAclRequest,
    MqttResponse,
    MqttSuperuserRequest,
    PolicyInput,
    Resource,
    Subject,
)
from celine.policies.models.core import ResourceType
from celine.policies.routes.deps import get_jwt_validator, get_policy_api

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mqtt", tags=["mqtt"])

MQTT_POLICY_PACKAGE = "celine.mqtt"


def _extract_subject_from_token(token: str, jwt_validator) -> Subject | None:
    """Extract subject from JWT token."""
    if token.count(".") == 2:
        try:
            claims = jwt_validator.validate(token)
            return extract_subject_from_claims(claims)
        except JWTValidationError:
            return None
    return None


def _acc_to_actions(acc: int) -> list[str]:
    """Convert mosquitto acc bitmask to action names."""
    actions: list[str] = []
    if acc & 0x04:
        actions.append("subscribe")
    if acc & 0x02:
        actions.append("publish")
    if acc & 0x01:
        actions.append("read")
    return actions or ["unknown"]


def _get_token_from_header(authorization: str | None) -> str | None:
    """Extract bearer token from Authorization header."""
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


@router.post("/user")
async def mqtt_auth(
    response: Response,
    authorization: str | None = Header(default=None),
    jwt_validator=Depends(get_jwt_validator),
    x_request_id: Annotated[str | None, Header()] = None,
) -> MqttResponse:
    """Authenticate MQTT client via JWT."""
    token = _get_token_from_header(authorization)
    if not token:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="missing token")

    subject = _extract_subject_from_token(token, jwt_validator)
    if subject is None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")

    return MqttResponse(ok=True, reason="authenticated")


@router.post("/acl")
async def mqtt_acl(
    request: MqttAclRequest,
    response: Response,
    authorization: str | None = Header(default=None),
    api: PolicyAPI = Depends(get_policy_api),
    jwt_validator=Depends(get_jwt_validator),
    x_request_id: Annotated[str | None, Header()] = None,
) -> MqttResponse:
    """Authorize MQTT topic access."""
    request_id = x_request_id or str(uuid.uuid4())

    token = _get_token_from_header(authorization)
    if not token:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="missing token")

    subject = _extract_subject_from_token(token, jwt_validator)
    if subject is None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")

    actions = _acc_to_actions(request.acc)

    for action_name in actions:
        policy_input = PolicyInput(
            subject=subject,
            resource=Resource(
                type=ResourceType.TOPIC,
                id=request.topic,
                attributes={},
            ),
            action=Action(name=action_name, context={}),
            environment={"request_id": request_id, "timestamp": time.time()},
        )

        try:
            result = api.evaluate(
                request_id=request_id,
                policy_package=MQTT_POLICY_PACKAGE,
                policy_input=policy_input,
                source_service="mqtt-broker",
            )

            if not result.decision.allowed:
                response.status_code = status.HTTP_403_FORBIDDEN
                return MqttResponse(ok=False, reason=result.decision.reason)

        except Exception as e:
            logger.exception("MQTT ACL check failed", exc_info=e)
            response.status_code = status.HTTP_403_FORBIDDEN
            return MqttResponse(ok=False, reason=f"check failed: {e}")

    return MqttResponse(ok=True, reason="authorized")


@router.post("/superuser")
async def mqtt_superuser(
    request: MqttSuperuserRequest,
    response: Response,
    authorization: str | None = Header(default=None),
    jwt_validator=Depends(get_jwt_validator),
    x_request_id: Annotated[str | None, Header()] = None,
) -> MqttResponse:
    """Check if client is MQTT superuser."""
    token = _get_token_from_header(authorization)
    if not token:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="missing token")

    subject = _extract_subject_from_token(token, jwt_validator)
    if subject is None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")

    if "mqtt.admin" in subject.scopes:
        return MqttResponse(ok=True, reason="superuser")

    response.status_code = status.HTTP_403_FORBIDDEN
    return MqttResponse(ok=False, reason="not superuser")
