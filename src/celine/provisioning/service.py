"""What each route does, with no FastAPI in it.

`routes.py` is authentication, scope checks and status codes; this is the work.
The split is what lets the whole of the behaviour be tested against a fake
Keycloak without a client, a token or an event loop full of HTTP.

## How an account is found, which is the whole design

Two questions, two answers, and they are different on purpose:

**The upsert has an address and no account yet.** `../onboarding` calls it for
somebody it has just approved, whose registry row does not exist — it writes that
row afterwards, with the username this call returns, which is what keeps the
registry single-writer and the step order fail-closed. So there is nothing to
look a member up by, and the address is the only identifier every writer agrees
on: find by email, create under the address if there is no match, and read the
username back from Keycloak because an account that already existed may
authenticate as something this platform never chose.

**The lifecycle calls have a member and no address.** A password reset or a
revocation is for somebody the registry already holds, and the registry's
`Member.user_id` *is* the username. So `(community, key)` resolves through the
registry export — the same artefact the sweep reads — and no address is needed
or asked for.

The asymmetry is not an inconsistency: each call resolves through the thing that
exists when it is made.

## Nothing here writes to the registry

`../onboarding` writes the member, with the username this service returned. That
keeps the registry's single-writer property and leaves the existing fail-closed
order intact: the login exists before the row that keys on it.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass

from celine.policies.cli.keycloak.client import KeycloakAdminClient
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.provisioning.bundle import (
    load_rec_community_info,
    load_rec_operators,
    load_rec_participants,
    participant_username,
)
from celine.provisioning.config import ProvisioningSettings
from celine.provisioning.models import OrganizationSpec
from celine.provisioning.provisioner import Provisioner
from celine.provisioning.registry import RegistryError, fetch_rec_documents, issuer_url

logger = logging.getLogger(__name__)

_PASSWORD_ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$"


class ProvisioningError(RuntimeError):
    """Something the caller has to be told about, with the subject named."""


class MemberNotFound(ProvisioningError):
    """No member, or no account for one, under the key this call named.

    Distinct from a Keycloak failure because the answer is different: this is a
    `404` the caller may well have expected, not an outage.
    """


def generate_password() -> str:
    """A one-time credential for a handover.

    Sixteen characters from an alphabet with no `l`, `1`, `O` or `0` in it,
    because the value is read aloud or retyped at least once before it is
    changed. Identical to the alphabet `sync-users` uses, deliberately: two
    handover conventions is one more than anybody can remember.
    """
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(16))


@dataclass(frozen=True)
class Divergence:
    """One member the sweep provisioned and then could not confirm."""

    key: str
    username: str
    kind: str
    detail: str = ""


@dataclass(frozen=True)
class UpsertResult:
    username: str
    keycloak_id: str
    created: bool


@dataclass(frozen=True)
class ResetResult:
    username: str
    keycloak_id: str
    password: str


@dataclass(frozen=True)
class DisableResult:
    username: str
    keycloak_id: str
    changed: bool


@dataclass(frozen=True)
class ReconcileResult:
    community: str
    members: int
    created: int
    existing: int
    divergences: tuple[Divergence, ...] = ()


class ProvisioningService:
    """The four operations, over an admin client it opens per call.

    **Stateless, and the connection is not an exception to that.** A client per
    call costs one token request and buys a service that cannot hold a stale
    token, a half-closed socket, or a realm it authenticated against before the
    realm was re-synced. Idempotency comes from the keys — the organization
    alias and the username — and from nothing remembered here, which is what
    makes a retry simply another call.
    """

    def __init__(
        self,
        settings: ProvisioningSettings,
        keycloak_settings: KeycloakSettings,
    ) -> None:
        self._settings = settings
        self._keycloak_settings = keycloak_settings

    # -- the upsert --------------------------------------------------------

    async def ensure_participant(
        self,
        *,
        community: str,
        key: str,
        email: str,
        first_name: str | None = None,
        last_name: str | None = None,
    ) -> UpsertResult:
        """Ensure an account exists for this member and is filed in its REC.

        Idempotent on `(community, key)` in the only sense that matters: a
        second call finds the account the first one made, joins nothing twice,
        and answers `created=False`.

        The REC organization is **ensured, not required**. A community whose
        organization does not exist yet is the ordinary state of a realm that
        has been synced but never swept, and refusing here would make the first
        onboarding of a new REC fail for a reason its operator cannot act on.
        """
        async with KeycloakAdminClient(self._keycloak_settings) as kc:
            await kc.authenticate()
            provisioner = Provisioner(kc)

            outcome = await provisioner.ensure_community(
                OrganizationSpec(alias=community, name=community)
            )

            existing = await provisioner.find_by_email(email)
            username = existing["username"] if existing else _username_from(email)

            participant = await provisioner.ensure_participant(
                username=username,
                org_id=outcome.org_id,
                member_group_id=outcome.member_group_id,
                email=email,
                first_name=first_name,
                last_name=last_name,
            )

            logger.info(
                "Provisioned %s/%s as '%s' (%s)",
                community,
                key,
                participant.username,
                "created" if participant.created else "existing",
            )
            return UpsertResult(
                username=participant.username,
                keycloak_id=participant.keycloak_id,
                created=participant.created,
            )

    # -- the lifecycle calls ----------------------------------------------

    async def reset_password(self, *, community: str, key: str) -> ResetResult:
        """Issue a one-time credential for a member the registry holds."""
        username = await self._username_of(community, key)
        password = generate_password()

        async with KeycloakAdminClient(self._keycloak_settings) as kc:
            await kc.authenticate()
            provisioner = Provisioner(kc)

            user = await provisioner.find_by_username(username)
            if not user:
                raise MemberNotFound(
                    f"{community}/{key} is registered as '{username}', and the "
                    f"realm has no such account. Provision it first."
                )

            await provisioner.reset_password(user["id"], password, temporary=True)
            logger.info("Reset password for %s/%s ('%s')", community, key, username)
            return ResetResult(
                username=username, keycloak_id=user["id"], password=password
            )

    async def disable(self, *, community: str, key: str) -> DisableResult:
        """Revoke a member's access without destroying anything."""
        username = await self._username_of(community, key)

        async with KeycloakAdminClient(self._keycloak_settings) as kc:
            await kc.authenticate()
            provisioner = Provisioner(kc)

            user = await provisioner.find_by_username(username)
            if not user:
                raise MemberNotFound(
                    f"{community}/{key} is registered as '{username}', and the "
                    f"realm has no such account. Nothing to disable."
                )

            changed = await provisioner.set_enabled(user["id"], False)
            logger.info(
                "Disabled %s/%s ('%s')%s",
                community,
                key,
                username,
                "" if changed else " — already disabled",
            )
            return DisableResult(
                username=username, keycloak_id=user["id"], changed=changed
            )

    # -- the sweep ---------------------------------------------------------

    async def reconcile(self, community: str) -> ReconcileResult:
        """Provision every active member the registry holds for one community,
        then check that every one of them is in its organization.

        **The check runs after the provisioning and its findings are a
        failure.** Everything it looks at is something this same call claimed to
        have done, so a divergence is not drift to be repaired next time — it is
        a provisioning call that reported success and had not succeeded. With
        one writer it should never happen, which is exactly when a check stops
        being run, so it fails loudly rather than repairing quietly.

        Members that are not `active` are skipped and **not** disabled: the
        registry keys a member as pending before approval and suspended or
        inactive after withdrawal, and skipping provisioning is a different act
        from revoking access, with a different owner and its own route.
        """
        document = await self._export(community)
        info = load_rec_community_info(document, source=f"registry/{community}")
        participants = load_rec_participants(document)
        operators = load_rec_operators(document)

        created = 0
        existing = 0
        divergences: list[Divergence] = []

        async with KeycloakAdminClient(self._keycloak_settings) as kc:
            await kc.authenticate()
            provisioner = Provisioner(kc)

            outcome = await provisioner.ensure_community(
                OrganizationSpec(
                    alias=info["id"],
                    name=info["name"],
                    description=info.get("description", ""),
                    type=info.get("type", "rec"),
                ),
                [
                    OrganizationSpec(
                        alias=op["id"],
                        name=op["name"],
                        description=op.get("contact") or "",
                        type="dso",
                    )
                    for op in operators
                ],
            )

            for member in participants:
                username = participant_username(member)
                # No credential. A member the sweep creates is one the registry
                # knows about and nobody has handed anything to; inventing a
                # password here would produce a secret that exists, grants
                # access and was never given to anybody.
                result = await provisioner.ensure_participant(
                    username=username,
                    org_id=outcome.org_id,
                    member_group_id=outcome.member_group_id,
                )
                if result.created:
                    created += 1
                else:
                    existing += 1

                if not await provisioner.is_in_organization(
                    outcome.org_id, result.keycloak_id
                ):
                    divergences.append(
                        Divergence(
                            key=member["key"],
                            username=username,
                            kind="not in the REC organization",
                            detail=(
                                "no `organization` claim, so no org-scoped policy "
                                "resolves them"
                            ),
                        )
                    )

        if divergences:
            logger.error(
                "Reconcile of %s left %d member(s) outside their organization",
                community,
                len(divergences),
            )

        return ReconcileResult(
            community=info["id"],
            members=len(participants),
            created=created,
            existing=existing,
            divergences=tuple(divergences),
        )

    # -- resolving a member through the registry ---------------------------

    async def _username_of(self, community: str, key: str) -> str:
        """What `(community, key)` authenticates as, per the registry row.

        `Member.user_id` is a Keycloak username and the registry is the row that
        owns it, so this reads rather than derives — deriving is how a second
        account appears beside the one somebody already signs in with.
        """
        document = await self._export(community)
        for member in load_rec_participants(document):
            if member["key"] == key:
                return participant_username(member)
        raise MemberNotFound(f"{community} has no member '{key}'")

    async def _export(self, community: str) -> dict:
        """The registry's bundle for one community.

        One export per call and no cache. A cache would be state, and the whole
        argument for this service being safe to retry is that it holds none — a
        stale member list is exactly the class of failure this plan exists to
        end.
        """
        if not self._settings.registry_url:
            raise ProvisioningError(
                "No registry configured. Set CELINE_PROVISIONING_REGISTRY_URL; "
                "reconcile and the lifecycle calls resolve members through it."
            )
        if not self._settings.registry_client_secret:
            raise ProvisioningError(
                f"No secret for registry client "
                f"'{self._settings.registry_client_id}'. Set "
                f"CELINE_PROVISIONING_REGISTRY_CLIENT_SECRET."
            )

        try:
            documents = await fetch_rec_documents(
                registry_url=self._settings.registry_url,
                issuer=issuer_url(
                    self._keycloak_settings.base_url, self._keycloak_settings.realm
                ),
                client_id=self._settings.registry_client_id,
                client_secret=self._settings.registry_client_secret,
                community_keys=[community],
                timeout=self._keycloak_settings.timeout,
            )
        except RegistryError as e:
            raise ProvisioningError(str(e)) from e

        if len(documents) != 1:
            # The export is narrowed to one key, so anything else means the
            # registry answered a question nobody asked.
            raise ProvisioningError(
                f"registry returned {len(documents)} documents for '{community}', "
                f"expected exactly one"
            )
        return documents[0]


def _username_from(email: str) -> str:
    """The username a *new* account gets, when nothing else has named one.

    Lower-cased and stripped, and that is the entire transformation. This is not
    parsing the address and infers nothing from it: it is choosing a handle for
    an account that does not exist yet, and `../onboarding` has always chosen
    the same one — so an account created here and an account created there are
    named alike, which is what keeps a re-run from making a second one.

    Nothing may do this to a username that comes *back* from Keycloak or from a
    registry row. Those are read verbatim; see `bundle.participant_username`.
    """
    return email.strip().lower()
