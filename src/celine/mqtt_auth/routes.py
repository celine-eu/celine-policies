"""FastAPI routes for MQTT authentication."""

import logging
import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response, status

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
    """
    try:
        # Validate JWT if JWKS URI is configured
        if settings.oidc_jwks_uri:
            user = JwtUser.from_token(
                token,
                verify=True,
                jwks_uri=settings.oidc_jwks_uri,
                issuer=settings.oidc_issuer,
                audience=settings.oidc_audience,
            )
        else:
            # Just decode without verification (dev mode)
            user = JwtUser.from_token(token, verify=False)

        # Extract scopes from claims
        scopes = user.claims.get("scope", "")
        if isinstance(scopes, str):
            scopes = scopes.split()
        elif not isinstance(scopes, list):
            scopes = []

        # Extract groups from claims
        groups = user.claims.get("groups", [])
        if not isinstance(groups, list):
            groups = []

        return Subject(
            id=user.sub,
            type=SubjectType.USER,
            groups=groups,
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
    return actions or ["unknown"]


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
    request: MqttAclRequest,
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
    request_id = x_request_id or str(uuid.uuid4())

    token = _get_token_from_header(authorization)
    if not token:
        logger.debug("MQTT ACL failed: missing token (topic=%s)", request.topic)
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="missing token")

    subject = _extract_subject_from_token(token, settings)
    if subject is None:
        logger.debug("MQTT ACL failed: invalid credentials (topic=%s)", request.topic)
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")

    # Convert acc bitmask to action names
    actions = _acc_to_actions(request.acc)

    # Check each action (publish, subscribe, read)
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
            decision = engine.evaluate_decision(
                policy_package=settings.mqtt_policy_package,
                policy_input=policy_input,
            )

            if not decision.allowed:
                logger.warning(
                    "MQTT ACL denied: user=%s topic=%s action=%s reason=%s",
                    subject.id,
                    request.topic,
                    action_name,
                    decision.reason,
                )
                response.status_code = status.HTTP_403_FORBIDDEN
                return MqttResponse(ok=False, reason=decision.reason)

        except Exception as e:
            logger.exception("MQTT ACL check failed: %s", e)
            response.status_code = status.HTTP_403_FORBIDDEN
            return MqttResponse(ok=False, reason=f"check failed: {e}")

    logger.info(
        "MQTT ACL allowed: user=%s topic=%s actions=%s",
        subject.id,
        request.topic,
        actions,
    )
    return MqttResponse(ok=True, reason="authorized")


@router.post("/superuser")
async def mqtt_superuser(
    request: MqttSuperuserRequest,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
    settings: MqttAuthSettings = Depends(get_settings),
) -> MqttResponse:
    """Check if client is MQTT superuser.

    Superusers bypass all ACL checks.

    Returns:
    - 200 + ok=true if superuser
    - 403 + ok=false if not superuser
    """
    token = _get_token_from_header(authorization)
    if not token:
        logger.debug("MQTT superuser check failed: missing token")
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="missing token")

    subject = _extract_subject_from_token(token, settings)
    if subject is None:
        logger.debug("MQTT superuser check failed: invalid credentials")
        response.status_code = status.HTTP_403_FORBIDDEN
        return MqttResponse(ok=False, reason="invalid credentials")

    # Check for superuser scope
    if settings.mqtt_superuser_scope in subject.scopes:
        logger.info("MQTT superuser: user=%s", subject.id)
        return MqttResponse(ok=True, reason="superuser")

    logger.debug("MQTT superuser check failed: user=%s", subject.id)
    response.status_code = status.HTTP_403_FORBIDDEN
    return MqttResponse(ok=False, reason="not superuser")
