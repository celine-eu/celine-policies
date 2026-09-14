"""What crosses the wire, and the one name that changes as it does.

`ParticipantResponse.user_id` is the **Keycloak uuid**, because that is what
`../onboarding` needs for its dataspace step. The registry's `Member.user_id`
column is a **username**. The two names collide across the seam and the
collision has already cost a defect, so the mapping happens here, once: the
package speaks `keycloak_id` everywhere inside and this module is the only place
it becomes `user_id`.
"""

from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field

# The three value sets below are `str` enums rather than bare `Literal`s for one
# reason: a named enum becomes a named component in the OpenAPI document, so
# the SDK generates `InvitationOutcome`, `InvitationSendOutcome` and `Locale`
# instead of `InvitationSchema` and `InvitationSchema1`, whose numbering depends
# on field order. On the wire they are the same strings.


class InvitationOutcome(str, Enum):
    """Why an upsert did, or did not, send an invitation.

    Mirrors `celine.provisioning.invitation.InvitationOutcome`. A stable reason
    code the consumer translates for the operator who approved.
    """

    not_requested = "not_requested"
    sent = "sent"
    has_password = "has_password"
    not_on_dev_list = "not_on_dev_list"
    account_disabled = "account_disabled"


class InvitationSendOutcome(str, Enum):
    """What `POST .../invitation` did: sent, or refused by the dev list."""

    sent = "sent"
    not_on_dev_list = "not_on_dev_list"


class Locale(str, Enum):
    """The languages the email and login themes carry.

    Keycloak stores any value it is given and silently falls back to the realm
    default for one it has no bundle for (measured), so the check is here.
    """

    it = "it"
    en = "en"
    es = "es"


class ParticipantUpsert(BaseModel):
    """The body of `PUT /participants/{community}/{key}`.

    **The email transits and is stored nowhere.** Not here — this service keeps
    no state at all — and not in the registry, which has no email column and is
    gaining none. It is on the account in Keycloak, which is where the address a
    person logs in with belongs.

    It is required because it is the only thing that can find an account this
    platform did not name. A participant who already has a login authenticates
    under whatever convention created it, and the address is the one identifier
    every writer agrees on.

    **A plain string, not `EmailStr`.** The address belongs to the submission
    `../onboarding` already validated and accepted; re-deciding here whether it
    is well formed would mean a person who has been approved cannot be given a
    login because two libraries disagree about their address. Non-empty is the
    whole check, and it exists so a missing value fails here rather than
    creating an account named the empty string.
    """

    email: str = Field(
        ...,
        min_length=1,
        description="The participant's address; used to find or create the account",
    )
    first_name: str | None = Field(default=None, description="Given name, optional")
    last_name: str | None = Field(default=None, description="Family name, optional")
    locale: Locale | None = Field(
        default=None,
        description=(
            "The participant's language, used for Keycloak's emails. Written on "
            "creation, and on an existing account only if it has none. Needs "
            "internationalization enabled on the realm, or Keycloak drops it."
        ),
    )
    invite: bool = Field(
        default=False,
        description=(
            "Email the participant a link to set their password — only if the "
            "account was created in this call or has no password. The outcome is "
            "in `invitation`; the upsert never fails because of it."
        ),
    )


class ParticipantResponse(BaseModel):
    """What the caller cannot compute and has to be told."""

    user_id: str = Field(
        ..., description="The Keycloak uuid of the account (not the registry's user_id)"
    )
    username: str = Field(
        ...,
        description=(
            "What this account authenticates as, read back from Keycloak. This is "
            "the value that becomes the registry's Member.user_id."
        ),
    )
    created: bool = Field(
        ..., description="Whether this call created the account. A retry returns false."
    )
    invitation: InvitationOutcome = Field(
        ...,
        description=(
            "What happened to the invitation: `not_requested` (invite was false), "
            "`sent`, `has_password` (nothing to invite to), `not_on_dev_list` "
            "(dev email mode, address not allowed), `account_disabled`."
        ),
    )
    invited: bool = Field(
        ..., description="True if and only if `invitation` is `sent`."
    )


class InvitationResponse(BaseModel):
    """What `POST .../invitation` emailed, and for how long the link lasts.

    No credential travels here: the person sets their own through the link
    Keycloak sends. `actions` says which email it was — `UPDATE_PASSWORD` and
    `VERIFY_EMAIL` for an account with no password (an invitation),
    `UPDATE_PASSWORD` alone for one that has a password (a reset).
    """

    user_id: str
    username: str
    invitation: InvitationSendOutcome = Field(
        ...,
        description="`sent`, or `not_on_dev_list` when dev email mode refused the address",
    )
    actions: list[str]
    lifespan: int = Field(..., description="Seconds the link stays usable")


class DisableResponse(BaseModel):
    """Whether the account was disabled, or already was.

    `changed` is false for a revocation that was already in force, which must
    not read as a revocation that just happened.
    """

    user_id: str
    username: str
    changed: bool


class DivergenceModel(BaseModel):
    """One member whose Keycloak state does not match the registry."""

    key: str
    username: str
    kind: str
    detail: str = ""


class ReconcileResponse(BaseModel):
    """What a community sweep did, and what it could not put right.

    `divergences` is empty on a healthy run **and a sweep that ends with any is
    a failure, reported as one**. The check runs after provisioning, so anything
    it finds is something a provisioning call claimed to have done and had not:
    quietly repairing it on the next sweep is how 10 of 45 members ended up
    outside their own organization with nothing saying so.
    """

    community: str
    members: int
    created: int
    existing: int
    divergences: list[DivergenceModel] = Field(default_factory=list)
