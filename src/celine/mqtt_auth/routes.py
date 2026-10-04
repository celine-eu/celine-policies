"""FastAPI routes for MQTT authentication."""

import logging
import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Header, Response, status, Request

from celine.mqtt_auth.config import MqttAuthSettings
from celine.mqtt_auth.models import (
    MqttAclRequest,
    MqttAuthRequest,
    MqttResponse,
    MqttSuperuserRequest,
)
from celine.sdk.auth import JwtUser
from celine.sdk.policies import (
    Action,
    CachedPolicyEngine,
    PolicyInput,
    Resource,
    ResourceType,
    Subject,
    SubjectType,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["MQTT Auth"])


def get_settings() -> MqttAuthSettings:
    """Get settings from app state."""
    # This will be overridden by dependency injection in main.py
    return MqttAuthSettings()


def get_engine() -> CachedPolicyEngine:
    """Get policy engine from app state."""
    # This will be overridden by dependency injection in main.py
    raise NotImplementedError("Engine not configured")


def _get_token_from_header(authorization: str | None) -> str | None:
    """Extract bearer token from Authorization header."""
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


def _extract_subject_from_token(
    token: str, settings: MqttAuthSettings
) -> Subject | None:
    """Extract subject from JWT token.

    Returns None if token is invalid.

    User or service is the token's kind (`is_service_account`), never whether it holds
    a group (REQ-0014). The subject carries **no groups**: a realm group grants nothing,
    an organization group counts only inside its organization and a topic names none, so
    no group of either level reaches the MQTT policy (ADR-0012). A service is judged by
    its scopes; a person's token is a user whatever scopes it carries.
    """
    try:
        # Validate JWT if JWKS URI is configured
        user = JwtUser.from_token(token, oidc=settings.oidc)

        # Extract scopes from claims
        scopes = user.claims.get("scope", "")
        if isinstance(scopes, str):
            scopes = scopes.split()
        elif not isinstance(scopes, list):
            scopes = []

        subject_type = SubjectType.SERVICE if user.is_service_account else SubjectType.USER

        return Subject(
            id=user.sub,
            type=subject_type,
            groups=[],
            scopes=scopes,
            claims=user.claims,
        )
    except Exception as e:
        logger.debug("Failed to extract subject from token: %s", e)
        return None


def _acc_to_actions(acc: int) -> list[str]:
    """Convert mosquitto acc bitmask to action names.

    Bitmask values:
    - 1 = read
    - 2 = publish
    - 4 = subscribe
    """
    actions: list[str] = []
    if acc & 0x04:  # 4
        actions.append("subscribe")
    if acc & 0x02:  # 2
        actions.append("publish")
    if acc & 0x01:  # 1
        actions.append("read")
    return actions or []


@router.post("/user")
async def mqtt_auth(
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
    settings: MqttAuthSettings = Depends(get_settings),
) -> MqttResponse:
    """Authenticate MQTT client via JWT.

    mosquitto-go-auth calls this endpoint with:
    - Authorization header: Bearer <jwt-token>
    - Body: username, password, clientid

    Returns:
    - 200 + ok=true if authenticated
    - 403 + ok=false if not authenticated
    """
    token = _get_token_from_header(authorization)
    if not token:
        logger.debug("MQTT auth failed: missing token")
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="missing token")

    subject = _extract_subject_from_token(token, settings)
    if subject is None:
        logger.debug("MQTT auth failed: invalid credentials")
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")

    logger.info("MQTT auth success: user=%s", subject.id)
    return MqttResponse(ok=True, reason="authenticated")


@router.post("/acl")
async def mqtt_acl(
    # request: MqttAclRequest,
    request: Request,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
    engine: CachedPolicyEngine = Depends(get_engine),
    settings: MqttAuthSettings = Depends(get_settings),
) -> MqttResponse:
    """Authorize MQTT topic access.

    mosquitto-go-auth calls this endpoint for each pub/sub operation.

    Returns:
    - 200 + ok=true if authorized
    - 403 + ok=false if not authorized
    """

    body: MqttAclRequest | None = None
    raw_body = await request.body()
    try:
        body = MqttAclRequest.model_validate_json(raw_body)
    except Exception as e:
        logger.warning(f"Failed to parse body: {raw_body}")
        raise HTTPException(500, "Failed to parse request body")

    request_id = x_request_id or str(uuid.uuid4())

    token = _get_token_from_header(authorization)
    if not token:
        logger.debug("MQTT ACL failed: missing token (topic=%s)", body.topic)
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="missing token")

    subject = _extract_subject_from_token(token, settings)
    if subject is None:
        logger.debug("MQTT ACL failed: invalid credentials (topic=%s)", body.topic)
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")

    # Convert acc bitmask to action names
    actions = _acc_to_actions(body.acc)
    if not actions:
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid acc mask")

    # Check each action (publish, subscribe, read)
    for action_name in actions:
        policy_input = PolicyInput(
            subject=subject,
            resource=Resource(
                type=ResourceType.TOPIC,
                id=body.topic,
                attributes={},
            ),
            action=Action(name=action_name, context={}),
            environment={"request_id": request_id, "timestamp": time.time()},
        )

        try:
            decision = engine.evaluate_decision(
                policy_package=settings.mqtt_policy_package,
                policy_input=policy_input,
            )

            if not decision.allowed:
                logger.warning(
                    "MQTT ACL denied: user=%s topic=%s action=%s reason=%s input=%s",
                    subject.id,
                    body.topic,
                    action_name,
                    decision.reason,
                    policy_input.model_dump_json(),
                )
                response.status_code = status.HTTP_403_FORBIDDEN
                return MqttResponse(ok=False, reason=decision.reason)

        except Exception as e:
            logger.exception("MQTT ACL check failed: %s", e)
            response.status_code = status.HTTP_403_FORBIDDEN
            return MqttResponse(ok=False, reason=f"check failed")

    logger.info(
        "MQTT ACL allowed: user=%s topic=%s actions=%s",
        subject.id,
        body.topic,
        actions,
    )
    return MqttResponse(ok=True, reason="authorized")


@router.post("/superuser")
async def mqtt_superuser(
    request: MqttSuperuserRequest,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
) -> MqttResponse:
    """There is no MQTT superuser: always 403 (REQ-0014, ADR-0012).

    mosquitto-go-auth may still be configured to ask (`auth_opt_disable_superuser false`
    in a deployment's broker); every answer is no, so every operation goes through `/acl`.
    No scope, group or role — `platform-admin` included — makes a client a superuser.
    """
    logger.debug("MQTT superuser check: always denied (user=%s)", request.username)
    response.status_code = status.HTTP_403_FORBIDDEN
    return MqttResponse(ok=False, reason="superuser disabled")
