"""The four routes, their scope checks, and their status codes.

Authorisation is by scope like every other celine service. **Ingress
restriction is defence in depth, not the control**: the argument that this
service is safe to hold realm-wide administration rests on nothing outside the
network being able to reach it, and a caller *inside* the network still presents
a token and still has to hold the scope.

`../onboarding` holds no Keycloak grant once it calls these. That is the point of
the whole plan: one writer, reached one way.

## Every error has one shape

`{"detail": {"code": "...", "message": "..."}}`, except FastAPI's own `422`.
`code` is the contract and `message` is a sentence for a person. The code comes
from the exception (`ProvisioningError.code`), so a route cannot answer a status
with a code that means something else.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from celine.provisioning.api_models import (
    DisableResponse,
    DivergenceModel,
    ErrorResponse,
    InvitationRequest,
    InvitationResponse,
    ParticipantResponse,
    ParticipantUpsert,
    ReconcileResponse,
)
from celine.provisioning.config import (
    SCOPE_ADMIN,
    SCOPE_PARTICIPANTS_WRITE,
    SCOPE_RECONCILE,
    ProvisioningSettings,
)
from celine.provisioning.service import (
    Conflict,
    InvitationCooldown,
    NotFound,
    ProvisioningError,
    ProvisioningService,
)
from celine.sdk.auth import JwtUser

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Provisioning"])


def _error(
    status_code: int,
    code: str,
    message: str,
    *,
    headers: dict[str, str] | None = None,
) -> HTTPException:
    """The one error body: `{"detail": {"code": ..., "message": ...}}`."""
    return HTTPException(
        status_code, {"code": code, "message": message}, headers=headers
    )


def _refusal(e: ProvisioningError) -> HTTPException:
    """Map a service exception to its status, carrying its own code.

    Order matters only in that subclasses come before their base: every
    `NotFound` is a `404`, every `Conflict` a `409`, and anything else that is a
    `ProvisioningError` is a dependency that failed (`502`), `send_failed`
    included.
    """
    if isinstance(e, NotFound):
        return _error(status.HTTP_404_NOT_FOUND, e.code, str(e))
    if isinstance(e, Conflict):
        return _error(status.HTTP_409_CONFLICT, e.code, str(e))
    if isinstance(e, InvitationCooldown):
        return _error(
            status.HTTP_429_TOO_MANY_REQUESTS,
            e.code,
            str(e),
            headers={"Retry-After": str(e.retry_after)},
        )
    return _error(status.HTTP_502_BAD_GATEWAY, e.code, str(e))


def _responses(*codes: int) -> dict[int | str, dict]:
    """Declare the error statuses a route answers, with the shared body, so the
    OpenAPI document says what the docs say."""
    described = {
        401: "No bearer token (`missing_token`), or it does not verify (`invalid_token`)",
        403: "The token lacks the scope (`insufficient_scope`)",
        404: "`community_not_found`, `member_not_found` or `account_not_found`",
        409: (
            "The account's state rules it out: `account_disabled`; on the "
            "invitation route also `has_password` (intent `invitation`), "
            "`no_password` (intent `password_reset`) and `no_email`"
        ),
        429: "Emailed within the cooldown (`cooldown`); see `Retry-After`",
        502: "A dependency failed: `registry_unavailable`, `send_failed`, `provisioning_failed`",
    }
    return {
        code: {"model": ErrorResponse, "description": described[code]} for code in codes
    }


def get_settings() -> ProvisioningSettings:
    """Overridden in `main.py` by the app's own settings."""
    return ProvisioningSettings()


def get_service() -> ProvisioningService:
    """Overridden in `main.py`. Never constructed by default — a service built
    from nothing would authenticate against a Keycloak nobody configured."""
    raise NotImplementedError("Provisioning service not configured")


def _token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _error(status.HTTP_401_UNAUTHORIZED, "missing_token", "missing bearer token")
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
        raise _error(status.HTTP_401_UNAUTHORIZED, "invalid_token", "invalid token") from e

    if not (user.has_scope(scope) or user.has_scope(SCOPE_ADMIN)):
        logger.warning("Refused %s: holds neither %s nor %s", user.sub, scope, SCOPE_ADMIN)
        raise _error(
            status.HTTP_403_FORBIDDEN, "insufficient_scope", f"requires scope '{scope}'"
        )
    return user


@router.put(
    "/participants/{community}/{key}",
    response_model=ParticipantResponse,
    responses=_responses(401, 403, 502),
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

    **`invite` does not change that.** A disabled account, an account that
    already has a password, one with no email address, one emailed within the
    cooldown, an address outside the dev list or a send Keycloak did not
    complete is still a `200`, with the reason in `invitation`, so an approval
    is never blocked by its email. `invite` only ever means an invitation.
    """
    _require_scope(authorization, settings, SCOPE_PARTICIPANTS_WRITE)

    try:
        result = await service.ensure_participant(
            community=community,
            key=key,
            email=body.email,
            first_name=body.first_name,
            last_name=body.last_name,
            locale=body.locale.value if body.locale else None,
            invite=body.invite,
        )
    except ProvisioningError as e:
        raise _refusal(e) from e

    return ParticipantResponse(
        user_id=result.keycloak_id,
        username=result.username,
        created=result.created,
        invitation=result.invitation,
        invited=result.invited,
    )


@router.post(
    "/participants/{community}/{key}/invitation",
    response_model=InvitationResponse,
    responses=_responses(401, 403, 404, 409, 429, 502),
    summary="Email a member an invitation, or a password reset, as the caller names",
)
async def send_invitation(
    community: str,
    key: str,
    body: InvitationRequest,
    authorization: Annotated[str | None, Header()] = None,
    settings: ProvisioningSettings = Depends(get_settings),
    service: ProvisioningService = Depends(get_service),
) -> InvitationResponse:
    """Keycloak emails the link; no credential is generated or returned.

    The body names the email: `invitation` for an account with no password,
    `password_reset` (short lifespan) for one that has one. A mismatch is `409`
    `has_password` or `no_password`, before any send or cooldown, and the
    service never picks the other email instead. `404` for a community, member
    or account that does not exist (the code says which), `409` for a disabled
    account or one with no email address (`no_email`), `429` within the
    cooldown of the last email to that account — sent by this route or by an
    upsert — and `502` `send_failed` when Keycloak did not send it, which starts
    no cooldown.
    """
    _require_scope(authorization, settings, SCOPE_PARTICIPANTS_WRITE)

    try:
        result = await service.send_invitation(
            community=community, key=key, intent=body.intent.value
        )
    except ProvisioningError as e:
        raise _refusal(e) from e

    return InvitationResponse(
        user_id=result.keycloak_id,
        username=result.username,
        invitation=result.invitation,
        actions=list(result.actions),
        lifespan=result.lifespan,
    )


@router.post(
    "/participants/{community}/{key}/disable",
    response_model=DisableResponse,
    responses=_responses(401, 403, 404, 502),
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
    except ProvisioningError as e:
        raise _refusal(e) from e

    return DisableResponse(
        user_id=result.keycloak_id,
        username=result.username,
        changed=result.changed,
    )


@router.post(
    "/reconcile/{community}",
    response_model=ReconcileResponse,
    responses={
        **_responses(401, 403, 404, 502),
        500: {
            "description": (
                "The sweep left divergences (`reconcile_diverged`). `detail` is the "
                "whole report, with `code` and `message` beside it"
            )
        },
    },
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
    except ProvisioningError as e:
        raise _refusal(e) from e

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
        # The report stays the body, so a consumer reading `divergences` out of
        # `detail` keeps working; `code` and `message` join it for the shape.
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            {
                "code": "reconcile_diverged",
                "message": (
                    f"reconcile of {result.community} left "
                    f"{len(result.divergences)} member(s) outside their organization"
                ),
                **body.model_dump(mode="json"),
            },
        )
    return body
