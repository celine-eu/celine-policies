"""What a provisioning call was asked to do, and what it found or changed.

Every method on `Provisioner` returns one of these rather than printing, because
the same call has two callers with two reporting conventions: `sync-users`
writes coloured lines to a terminal, the service returns JSON. What is common to
both is *what happened*, and that is what these carry.

**`ParticipantOutcome.keycloak_id` is the uuid, not the registry's `user_id`.**
The two names collide across the seam and the collision is expensive: the
registry's `Member.user_id` column holds a Keycloak **username**, while
Keycloak's own `user_id` is the uuid. This package never uses the name `user_id`
for either, so nothing here can be read the wrong way; the service's response
model maps `keycloak_id` onto the wire name `user_id` at the boundary, once, in
one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class OrganizationSpec:
    """One Keycloak organization to ensure, as the registry describes it.

    `type` lands in the organization's `type` attribute, which is what tells a
    REC from a distribution system operator. It is the community's declared type
    for a REC and `dso` for an operator; nothing infers it.
    """

    alias: str
    name: str
    description: str = ""
    type: str = "rec"


@dataclass(frozen=True)
class OrganizationOutcome:
    """What ensuring one organization found or created.

    `member_group_id` is the org group new members are filed in — `viewers`, the
    least privileged of `ROLE_HIERARCHY`. It is returned rather than looked up
    again because ensuring the groups already resolved it, and a second lookup
    is a second chance to disagree.
    """

    alias: str
    org_id: str
    created: bool
    groups_created: tuple[str, ...] = ()
    member_group_id: str | None = None


@dataclass(frozen=True)
class CommunityOutcome:
    """A REC and the operators that serve it, ensured together.

    They travel together because they are ensured together: an operator is not a
    community and is not reconciled on its own, it exists because a community
    named it.
    """

    community: OrganizationOutcome
    operators: tuple[OrganizationOutcome, ...] = ()

    @property
    def org_id(self) -> str:
        return self.community.org_id

    @property
    def member_group_id(self) -> str | None:
        return self.community.member_group_id


@dataclass(frozen=True)
class ParticipantOutcome:
    """What ensuring one participant found or changed.

    `created` is the caller's whole idempotency signal: a retry of the same
    `PUT` is a second call with `created=False`, and nothing else about the
    account differs.

    `username` is read back from Keycloak rather than echoed from the request.
    An account that already existed may authenticate under a convention this
    call did not choose — `../../onboarding` names one after the address the
    person gave, a seed file names one after the member key — and the caller
    stores what the account *is* called, never what it asked for.
    """

    username: str
    keycloak_id: str
    created: bool
    org_joined: bool = False
    org_group_joined: bool = False
    realm_groups_joined: tuple[str, ...] = field(default_factory=tuple)
    password_set: bool = False
