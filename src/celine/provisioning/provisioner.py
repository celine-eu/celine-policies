"""The calls that put a participant into the realm, with nothing around them.

Extracted verbatim from `keycloak sync-users`, which is still the only caller
until the service lands. What moved is the Admin API sequence; what stayed
behind is the reporting, the dry-run branch, the password policy and the
registry reading — all of which are the CLI's, not provisioning's.

## The order is load-bearing in one place

A participant is created, *then* joined to the organization, *then* filed in its
org group. Keycloak will not accept the membership of a user it has not got, and
`ensure_user_in_org_group` addresses the group by the organization that owns it,
so neither call is reorderable. Everything else here is ensure-shaped and
idempotent by construction.

## What this does not do

**It does not read a registry and it does not decide who should exist.** It is
handed a participant and told which organization to file them in. Deciding that
is the caller's, and the two callers decide it differently — `sync-users`
reconciles every active member of a bundle, the service answers one `PUT`.

**It does not touch realm structure.** Claim scopes, the realm's own
`ROLE_HIERARCHY` groups and the oauth2-proxy audience mapper are properties of
the realm rather than of a community; `keycloak sync` owns them and
`sync-users` ensures them before it gets here.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping

from celine.policies.cli.keycloak.client import KeycloakAdminClient, ROLE_HIERARCHY
from celine.provisioning.invitation import has_password
from celine.provisioning.models import (
    CommunityOutcome,
    OrganizationOutcome,
    OrganizationSpec,
    ParticipantOutcome,
)

logger = logging.getLogger(__name__)

#: The org group a participant is filed in. The least privileged of
#: `ROLE_HIERARCHY` — a member is a viewer of their own community until somebody
#: decides otherwise, and nothing here promotes anybody.
MEMBER_GROUP = "viewers"


class Provisioner:
    """Writes participant accounts, their organizations and their memberships.

    Holds an authenticated `KeycloakAdminClient` and adds no state of its own: a
    retry is another call, and idempotency comes from the keys — the
    organization alias and the username — rather than from anything remembered
    here. That is what lets the service in front of it be stateless.
    """

    def __init__(self, kc: KeycloakAdminClient) -> None:
        self._kc = kc

    # -- organizations -----------------------------------------------------

    async def ensure_organization(self, spec: OrganizationSpec) -> OrganizationOutcome:
        """Ensure one organization, its org roles and its org groups.

        The roles and the groups are both the whole of `ROLE_HIERARCHY`, and
        both are ensured every time rather than only on creation: an
        organization that predates a name being added to the hierarchy is
        repaired by the next run, which is the only repair there is.
        """
        kc = self._kc
        org_id, created = await kc.ensure_organization(
            alias=spec.alias,
            name=spec.name,
            description=spec.description,
            attributes={"type": [spec.type]},
        )

        for role_name in ROLE_HIERARCHY:
            await kc.ensure_org_role(org_id, role_name)

        groups_created: list[str] = []
        member_group_id: str | None = None
        for group_name in ROLE_HIERARCHY:
            group_id, group_created = await kc.ensure_org_group(org_id, group_name)
            if group_created:
                groups_created.append(group_name)
            if group_name == MEMBER_GROUP:
                member_group_id = group_id

        return OrganizationOutcome(
            alias=spec.alias,
            org_id=org_id,
            created=created,
            groups_created=tuple(groups_created),
            member_group_id=member_group_id,
        )

    async def ensure_community(
        self,
        community: OrganizationSpec,
        operators: Iterable[OrganizationSpec] = (),
    ) -> CommunityOutcome:
        """Ensure a REC and the operators that serve it.

        Operators first, deliberately: an operator organization is shared
        between communities, so ensuring it before the REC means a run that
        fails half way has still made the shared thing rather than the tenant
        thing.
        """
        operator_outcomes = tuple(
            [await self.ensure_organization(spec) for spec in operators]
        )
        return CommunityOutcome(
            community=await self.ensure_organization(community),
            operators=operator_outcomes,
        )

    # -- participants ------------------------------------------------------

    async def ensure_participant(
        self,
        *,
        username: str,
        org_id: str,
        member_group_id: str | None = None,
        realm_group_ids: Mapping[str, str] | None = None,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        email_verified: bool = False,
        password: str | None = None,
        temporary: bool = True,
        reset_password: bool = False,
        locale: str | None = None,
    ) -> ParticipantOutcome:
        """Ensure one account exists and is filed where this REC expects it.

        `password` is only ever applied on creation, unless `reset_password`
        asks for it on an account that already existed. Resetting somebody's
        credential because a reconcile ran is not idempotence, it is a denial of
        service with a schedule, so it is opt-in and stays that way.

        `realm_group_ids` maps a group path to its id, resolved by the caller
        before any user is touched. Resolution does not happen here on purpose:
        a missing group must stop a run before it has provisioned half of it,
        and this method only ever sees one participant.

        `locale` is written on creation, and on an existing account **only when
        it has none**: an account that already carries one may carry the
        person's own choice, and an approval is not a reason to overrule it.
        """
        kc = self._kc

        keycloak_id, created = await kc.ensure_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            email_verified=email_verified,
            temporary_password=password,
            temporary=temporary,
            locale=locale,
        )

        if locale and not created:
            await self.ensure_locale(keycloak_id, locale)

        org_joined = await kc.ensure_user_in_organization(org_id, keycloak_id)

        org_group_joined = False
        if member_group_id:
            await kc.ensure_user_in_org_group(org_id, member_group_id, keycloak_id)
            org_group_joined = True

        joined_paths: list[str] = []
        for path, group_id in (realm_group_ids or {}).items():
            await kc.add_user_to_group_with_retry(keycloak_id, group_id)
            joined_paths.append(path)

        password_set = created and password is not None
        if not created and reset_password and password is not None:
            await kc.set_user_password(keycloak_id, password, temporary=temporary)
            password_set = True

        return ParticipantOutcome(
            username=username,
            keycloak_id=keycloak_id,
            created=created,
            org_joined=org_joined,
            org_group_joined=org_group_joined,
            realm_groups_joined=tuple(joined_paths),
            password_set=password_set,
        )

    # -- finding an account somebody else may have named -------------------

    async def find_by_id(self, keycloak_id: str) -> "dict | None":
        """The account with this Keycloak uuid, or None."""
        return await self._kc.get_user_by_id(keycloak_id)

    async def find_by_username(self, username: str) -> "dict | None":
        """The account with this exact username, or None."""
        return await self._kc.get_user_by_username(username)

    async def find_by_email(self, email: str) -> "dict | None":
        """The account with this exact address, or None.

        The address is the only identifier every writer agrees on, so it is how
        an account that already exists is found when nobody here chose its
        username. See `KeycloakAdminClient.get_user_by_email`.
        """
        return await self._kc.get_user_by_email(email)

    # -- lifecycle ---------------------------------------------------------

    async def ensure_locale(self, keycloak_id: str, locale: str) -> bool:
        """Give an existing account a locale if it has none. Returns whether it wrote."""
        user = await self._kc.get_user_by_id(keycloak_id)
        if user is None or (user.get("attributes") or {}).get("locale"):
            return False
        return await self._kc.set_user_locale(keycloak_id, locale)

    async def has_password(self, keycloak_id: str) -> bool:
        """Whether the account holds a password credential."""
        return has_password(await self._kc.get_user_credentials(keycloak_id))

    async def send_actions_email(
        self,
        keycloak_id: str,
        actions: tuple[str, ...],
        *,
        lifespan: int,
        client_id: str | None = None,
        redirect_uri: str | None = None,
    ) -> None:
        """Have Keycloak email the account a link performing `actions`.

        No password is generated, carried or returned: the person sets their
        own through the link. The caller has already decided the account is
        enabled and the address may be emailed — see `celine.provisioning.invitation`.
        """
        await self._kc.execute_actions_email(
            keycloak_id,
            list(actions),
            lifespan=lifespan,
            client_id=client_id,
            redirect_uri=redirect_uri,
        )

    async def set_enabled(self, keycloak_id: str, enabled: bool) -> bool:
        """Disable or re-enable an account. Returns whether it changed.

        Revocation is disabling and not deletion. The account, its memberships
        and everything keyed on its uuid survive, and reversing it is one call —
        which matters because the thing being revoked is somebody's access to
        their own energy community, not a mistake to be erased.
        """
        return await self._kc.set_user_enabled(keycloak_id, enabled)

    async def is_in_organization(self, org_id: str, keycloak_id: str) -> bool:
        """Whether the account is a member of the organization.

        Read-only, and the one question the reconcile sweep asks of every member
        it has just provisioned — see `celine.provisioning.service`.
        """
        return await self._kc.is_user_in_organization(org_id, keycloak_id)

    async def get_organization(self, alias: str) -> "dict | None":
        """The organization with this alias, or None. Creates nothing."""
        return await self._kc.get_organization_by_alias(alias)
