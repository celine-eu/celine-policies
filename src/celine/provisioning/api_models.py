"""What crosses the wire, and the one name that changes as it does.

`ParticipantResponse.user_id` is the **Keycloak uuid**, because that is what
`../onboarding` needs for its dataspace step. The registry's `Member.user_id`
column is a **username**. The two names collide across the seam and the
collision has already cost a defect, so the mapping happens here, once: the
package speaks `keycloak_id` everywhere inside and this module is the only place
it becomes `user_id`.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


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


class PasswordResetResponse(BaseModel):
    """The one-time credential, and who it belongs to.

    Temporary by construction: the participant is made to change it at next
    login, so what travels back here is a handover and never their password.
    """

    user_id: str
    username: str
    temporary_password: str


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
