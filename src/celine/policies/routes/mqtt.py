"""MQTT authorization endpoints (mosquitto-go-auth compatible)."""

import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Header, Request, Response, status

from celine.policies.api import PolicyAPI
from celine.policies.auth import JWTValidationError
from celine.policies.auth.subject import extract_subject_from_claims
from celine.policies.engine.engine import PolicyEngine
from celine.policies.models import (
    Action,
    MqttAclRequest,
    MqttAuthRequest,
    MqttResponse,
    MqttSuperuserRequest,
    PolicyInput,
    Resource,
    Subject,
)
from celine.policies.models.core import ResourceType
from celine.policies.routes.deps import (
    get_jwt_validator,
    get_policy_api,
    get_policy_engine,
)

router = APIRouter(prefix="/mqtt", tags=["mqtt"])


def _extract_subject_from_username(token: str, jwt_validator) -> Subject | None:
    if token.count(".") == 2:
        try:
            claims = jwt_validator.validate(token)
            return extract_subject_from_claims(claims)
        except JWTValidationError:
            return None
    return None


def _acc_to_actions(acc: int) -> list[str]:
    actions: list[str] = []
    if acc & 0x04:
        actions.append("subscribe")
    if acc & 0x02:
        actions.append("publish")
    if acc & 0x01:
        actions.append("read")
    return actions or ["unknown"]


@router.post("/user")
async def mqtt_auth(
    response: Response,
    authorization: str | None = Header(default=None),
    jwt_validator=Depends(get_jwt_validator),
    x_request_id: Annotated[str | None, Header()] = None,
) -> MqttResponse:
    request_id = x_request_id or str(uuid.uuid4())

    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()

    if not token:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="Missing token")

    subject = _extract_subject_from_username(token, jwt_validator)
    if subject is None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")

    return MqttResponse(ok=True, reason="authenticated")


@router.post("/acl")
async def mqtt_acl(
    request: Request,
    response: Response,
    api: PolicyAPI = Depends(get_policy_api),
    jwt_validator=Depends(get_jwt_validator),
    x_request_id: Annotated[str | None, Header()] = None,
) -> MqttResponse:
    request_id = x_request_id or str(uuid.uuid4())

    json = await request.json()
    print("JSON", json)

    # subject = _extract_subject_from_username(request.username, jwt_validator)
    # if subject is None:
    #     response.status_code = status.HTTP_403_FORBIDDEN
    #     return MqttResponse(ok=False, reason="invalid credentials")

    # actions = _acc_to_actions(request.acc)
    # base_env = {
    #     "request_id": request_id,
    #     "timestamp": time.time(),
    #     "clientid": request.clientid,
    #     "acc": request.acc,
    # }

    # for idx, action_name in enumerate(actions):
    #     eval_request_id = (
    #         request_id if len(actions) == 1 else f"{request_id}:{idx}:{action_name}"
    #     )
    #     policy_input = PolicyInput(
    #         subject=subject,
    #         resource=Resource(
    #             type=ResourceType.TOPIC,
    #             id=request.topic,
    #             attributes={"clientid": request.clientid},
    #         ),
    #         action=Action(name=action_name, context={"acc": request.acc}),
    #         environment=base_env,
    #     )
    #     result = api.evaluate(
    #         request_id=eval_request_id,
    #         policy_package="celine.mqtt.acl",
    #         policy_input=policy_input,
    #         source_service="mosquitto",
    #     )
    #     if not result.decision.allowed:
    #         response.status_code = status.HTTP_403_FORBIDDEN
    #         return MqttResponse(
    #             ok=False,
    #             reason=result.decision.reason or f"denied for action {action_name}",
    #         )

    return MqttResponse(ok=True, reason="authorized")


@router.post("/superuser")
async def mqtt_superuser(
    request: MqttSuperuserRequest,
    response: Response,
    engine: PolicyEngine = Depends(get_policy_engine),
    jwt_validator=Depends(get_jwt_validator),
    x_request_id: Annotated[str | None, Header()] = None,
) -> MqttResponse:
    request_id = x_request_id or str(uuid.uuid4())

    subject = _extract_subject_from_username(request.username, jwt_validator)
    if subject is None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")

    policy_input = PolicyInput(
        subject=subject,
        resource=Resource(type=ResourceType.TOPIC, id="*", attributes={}),
        action=Action(name="superuser", context={}),
        environment={"request_id": request_id, "timestamp": time.time()},
    )

    try:
        input_dict = engine.build_input_dict(policy_input)
        is_superuser = bool(
            engine.evaluate("data.celine.mqtt.acl.superuser", input_dict).get(
                "value", False
            )
        )
        if not is_superuser:
            response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(
            ok=is_superuser, reason="superuser" if is_superuser else "not superuser"
        )
    except Exception as e:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason=f"check failed: {e}")
