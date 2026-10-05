"""FastAPI routes for MQTT authentication.

**What is logged (REQ-0019).** A refused `/user` or `/acl` that presented a token
is one `celine.audit` record (`audit_denied`) naming the caller by `sub` and
client id, the topic, the verb and a short reason. Nothing else about the token
is written anywhere: no claim, no policy input. An allowed ACL check is not
audited — the broker asks for every publish and subscribe — and leaves at most a
DEBUG line with the topic and verbs.
"""

import logging
import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Header, Response, status, Request

from celine.sdk.audit import audit_denied

from celine.mqtt_auth.config import SERVICE_NAME, MqttAuthSettings
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
    request: Request,
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
        # The token did not verify, so nothing in it names a caller.
        audit_denied(
            "mqtt.connect", reason="invalid_token", service=SERVICE_NAME, request=request
        )
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
    except Exception:
        # The body is not logged: it carries the broker's username field.
        logger.warning("Failed to parse ACL request body (%d bytes)", len(raw_body))
        raise HTTPException(500, "Failed to parse request body")

    request_id = x_request_id or str(uuid.uuid4())

    token = _get_token_from_header(authorization)
    if not token:
        logger.debug("MQTT ACL failed: missing token (topic=%s)", body.topic)
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="missing token")

    subject = _extract_subject_from_token(token, settings)
    if subject is None:
        audit_denied(
            "mqtt.acl",
            resource=body.topic,
            reason="invalid_token",
            service=SERVICE_NAME,
            request=request,
            request_id=request_id,
        )
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")

    def denied(action: str, reason: str) -> None:
        audit_denied(
            action,
            caller=subject.claims,
            resource=body.topic,
            reason=reason,
            service=SERVICE_NAME,
            request=request,
            request_id=request_id,
        )

    # Convert acc bitmask to action names
    actions = _acc_to_actions(body.acc)
    if not actions:
        denied("mqtt.acl", "invalid_acc_mask")
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
                # The policy's reason is a fixed string of the bundle, never
                # the input; the input (claims included) is not logged.
                denied(f"mqtt.{action_name}", decision.reason or "denied")
                response.status_code = status.HTTP_403_FORBIDDEN
                return MqttResponse(ok=False, reason=decision.reason)

        except Exception as e:
            logger.exception("MQTT ACL check failed: %s", type(e).__name__)
            denied(f"mqtt.{action_name}", "check_failed")
            response.status_code = status.HTTP_403_FORBIDDEN
            return MqttResponse(ok=False, reason="check failed")

    # Not audited: the broker asks for every publish and subscribe.
    logger.debug("MQTT ACL allowed: topic=%s actions=%s", body.topic, actions)
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
    logger.debug("MQTT superuser check: always denied")
    response.status_code = status.HTTP_403_FORBIDDEN
    return MqttResponse(ok=False, reason="superuser disabled")
