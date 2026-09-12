"""The four routes, their scope checks, and their status codes.

Authorisation is by scope like every other celine service. **Ingress
restriction is defence in depth, not the control**: the argument that this
service is safe to hold realm-wide administration rests on nothing outside the
network being able to reach it, and a caller *inside* the network still presents
a token and still has to hold the scope.

`../onboarding` holds no Keycloak grant once it calls these. That is the point of
the whole plan: one writer, reached one way.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from celine.provisioning.api_models import (
    DisableResponse,
    DivergenceModel,
    ParticipantResponse,
    ParticipantUpsert,
    PasswordResetResponse,
    ReconcileResponse,
)
from celine.provisioning.config import (
    SCOPE_ADMIN,
    SCOPE_PARTICIPANTS_WRITE,
    SCOPE_RECONCILE,
    ProvisioningSettings,
)
from celine.provisioning.service import (
    MemberNotFound,
    ProvisioningError,
    ProvisioningService,
)
from celine.sdk.auth import JwtUser

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Provisioning"])


def get_settings() -> ProvisioningSettings:
    """Overridden in `main.py` by the app's own settings."""
    return ProvisioningSettings()


def get_service() -> ProvisioningService:
    """Overridden in `main.py`. Never constructed by default — a service built
    from nothing would authenticate against a Keycloak nobody configured."""
    raise NotImplementedError("Provisioning service not configured")


def _token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def _require_scope(
    authorization: str | None, settings: ProvisioningSettings, scope: str
) -> JwtUser:
    """Verify the token and refuse a caller that does not hold `scope`.

    `provisioning.admin` satisfies any of them, which is the admin-override rule
    `clients.yaml` documents and every other service honours — stated here
    rather than inherited, because a scope check that quietly differs from the
    convention is worse than one that repeats it.

    A bad token is `401` and a good token without the scope is `403`. The
    difference is what an operator does next: renew a credential, or ask for a
    grant.
    """
    try:
        user = JwtUser.from_token(_token(authorization), oidc=settings.oidc)
    except HTTPException:
        raise
    except Exception as e:
        logger.debug("Token rejected: %s", e)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from e

    if not (user.has_scope(scope) or user.has_scope(SCOPE_ADMIN)):
        logger.warning("Refused %s: holds neither %s nor %s", user.sub, scope, SCOPE_ADMIN)
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires scope '{scope}'")
    return user


@router.put(
    "/participants/{community}/{key}",
    response_model=ParticipantResponse,
    summary="Ensure a participant's account, organization and org group",
)
async def upsert_participant(
    community: str,
    key: str,
    body: ParticipantUpsert,
    authorization: Annotated[str | None, Header()] = None,
    settings: ProvisioningSettings = Depends(get_settings),
    service: ProvisioningService = Depends(get_service),
) -> ParticipantResponse:
    """Find or create the account, and file it in the REC.

    Synchronous rather than a signal, because the caller needs the `username`
    back: it becomes the registry's `Member.user_id`, and it is read from
    Keycloak rather than computed — an account that already existed may
    authenticate under a convention nobody here chose.

    Always `200`. A create and a no-op are the same request with the same
    meaning, and `created` in the body says which happened; a `201` on one and a
    `200` on the other would make a retry look like a different outcome.
    """
    _require_scope(authorization, settings, SCOPE_PARTICIPANTS_WRITE)

    try:
        result = await service.ensure_participant(
            community=community,
            key=key,
            email=body.email,
            first_name=body.first_name,
            last_name=body.last_name,
        )
    except ProvisioningError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e

    return ParticipantResponse(
        user_id=result.keycloak_id,
        username=result.username,
        created=result.created,
    )


@router.post(
    "/participants/{community}/{key}/password-reset",
    response_model=PasswordResetResponse,
    summary="Issue a one-time credential for a member",
)
async def reset_password(
    community: str,
    key: str,
    authorization: Annotated[str | None, Header()] = None,
    settings: ProvisioningSettings = Depends(get_settings),
    service: ProvisioningService = Depends(get_service),
) -> PasswordResetResponse:
    """The credential is temporary: the participant must change it at next
    login, so what comes back is a handover and never their password."""
    _require_scope(authorization, settings, SCOPE_PARTICIPANTS_WRITE)

    try:
        result = await service.reset_password(community=community, key=key)
    except MemberNotFound as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e)) from e
    except ProvisioningError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e

    return PasswordResetResponse(
        user_id=result.keycloak_id,
        username=result.username,
        temporary_password=result.password,
    )


@router.post(
    "/participants/{community}/{key}/disable",
    response_model=DisableResponse,
    summary="Revoke a member's access",
)
async def disable_participant(
    community: str,
    key: str,
    authorization: Annotated[str | None, Header()] = None,
    settings: ProvisioningSettings = Depends(get_settings),
    service: ProvisioningService = Depends(get_service),
) -> DisableResponse:
    """Disables the account. Nothing is deleted and re-enabling is one call —
    what is being revoked is somebody's access to their own energy community."""
    _require_scope(authorization, settings, SCOPE_PARTICIPANTS_WRITE)

    try:
        result = await service.disable(community=community, key=key)
    except MemberNotFound as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e)) from e
    except ProvisioningError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e

    return DisableResponse(
        user_id=result.keycloak_id,
        username=result.username,
        changed=result.changed,
    )


@router.post(
    "/reconcile/{community}",
    response_model=ReconcileResponse,
    summary="Sweep one community from the registry",
)
async def reconcile(
    community: str,
    authorization: Annotated[str | None, Header()] = None,
    settings: ProvisioningSettings = Depends(get_settings),
    service: ProvisioningService = Depends(get_service),
) -> ReconcileResponse:
    """Provision every active member the registry holds, then assert that each
    is in the REC's organization.

    **A sweep that ends with a divergence answers `500`**, with the divergences
    in the body. Everything checked is something this same call claimed to have
    done, so a finding is a provisioning call that reported success and had not
    succeeded — a `200` with a list nobody reads is how 10 of 45 members ended
    up outside their own organization with nothing saying so.

    What calls this on a schedule is a deployment concern. The route is the
    entry point and nothing here is a scheduler.
    """
    _require_scope(authorization, settings, SCOPE_RECONCILE)

    try:
        result = await service.reconcile(community)
    except MemberNotFound as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e)) from e
    except ProvisioningError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e

    body = ReconcileResponse(
        community=result.community,
        members=result.members,
        created=result.created,
        existing=result.existing,
        divergences=[
            DivergenceModel(
                key=d.key, username=d.username, kind=d.kind, detail=d.detail
            )
            for d in result.divergences
        ],
    )
    if result.divergences:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, body.model_dump(mode="json")
        )
    return body
