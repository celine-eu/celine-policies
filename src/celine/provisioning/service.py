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

**The lifecycle calls have a member and no address.** An invitation or a
revocation is for somebody the registry already holds, and the registry's
`Member.user_id` *is* the username. So `(community, key)` resolves through the
registry export — the same artefact the sweep reads — and no address is needed
or asked for.

The asymmetry is not an inconsistency: each call resolves through the thing that
exists when it is made.

## No password is generated here

An account gets a credential only by the person setting it, through a link
Keycloak emails them. The upsert invites when asked, and only an account that
was created in that call or has no password; `POST .../invitation` sends the
email its caller names — an invitation to an account without a password, or a
reset to one that has one — and refuses the other. See
`celine.provisioning.invitation` for the recipient guard both apply.

## Nothing here writes to the registry

`../onboarding` writes the member, with the username this service returned. That
keeps the registry's single-writer property and leaves the existing fail-closed
order intact: the login exists before the row that keys on it.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from celine.policies.cli.keycloak.client import KeycloakAdminClient, KeycloakError
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.provisioning.bundle import (
    load_rec_community_info,
    load_rec_operators,
    load_rec_participants,
    participant_username,
)
from celine.provisioning.config import ProvisioningSettings
from celine.provisioning.invitation import (
    INVITE_ACTIONS,
    RESET_ACTIONS,
    InvitationOutcome,
    SendIntent,
    has_address,
)
from celine.provisioning.models import OrganizationSpec
from celine.provisioning.provisioner import Provisioner
from celine.provisioning.registry import (
    RegistryCommunityNotFound,
    RegistryError,
    fetch_rec_documents,
    issuer_url,
)

logger = logging.getLogger(__name__)


class ProvisioningError(RuntimeError):
    """Something the caller has to be told about, with the subject named.

    `code` is the stable, machine-readable half of the answer and the message is
    the human half. Routes put both in the error body, so a consumer branches on
    the code and never parses the sentence. A subclass that answers differently
    sets its own code; this base is a dependency that failed (`502`).
    """

    code: str = "provisioning_failed"


class RegistryUnavailable(ProvisioningError):
    """The registry could not be read, or is not configured. A `502`."""

    code = "registry_unavailable"


class NotFound(ProvisioningError):
    """Something the call named does not exist. A `404` the caller may well have
    expected, not an outage. Always one of the subclasses below, so the code
    says *which* thing is missing."""

    code = "not_found"


class CommunityNotFound(NotFound):
    """The registry has no community under this key."""

    code = "community_not_found"


class MemberNotFound(NotFound):
    """The registry's community has no active member under this key."""

    code = "member_not_found"


class AccountNotFound(NotFound):
    """The registry has the member, and the realm has no account for it."""

    code = "account_not_found"


class Conflict(ProvisioningError):
    """The account exists and its state rules out what was asked. A `409`,
    always one of the subclasses below, so the code says which state."""

    code = "conflict"


class AccountDisabled(Conflict):
    """The account exists and is disabled, so nothing may be sent to it.

    Checked by this service before Keycloak is asked, because Keycloak's own
    answer is a `400` whose message is not a contract. A `409`.
    """

    code = "account_disabled"


class HasPassword(Conflict):
    """An invitation was asked for an account that already has a password.

    Refused, not turned into a reset: the email must be the one the person
    pressed for (requester, 2026-09-14, A2). Before any send or cooldown. A `409`.
    """

    code = "has_password"


class NoPassword(Conflict):
    """A password reset was asked for an account that has no password.

    Refused, never turned into an invitation (requester, 2026-09-14, A2). Before
    any send or cooldown. A `409`.
    """

    code = "no_password"


class NoEmail(Conflict):
    """The account has no email address, so there is nobody to write to.

    Whatever the email mode, and before the dev list and the cooldown: it is a
    fact about the account, not a deployment's refusal. Keycloak would answer
    `400 User email missing`. A `409` on the route, `invitation: no_email` on
    the upsert.
    """

    code = "no_email"


class InvitationCooldown(ProvisioningError):
    """The same account was sent an email too recently. A `429` on the route,
    `invitation: cooldown` on the upsert."""

    code = "cooldown"

    def __init__(self, message: str, *, retry_after: int) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class SendFailed(ProvisioningError):
    """Keycloak was asked to send the email and did not.

    Keycloak answers `500 {"errorMessage": "Failed to send execute actions
    email: …"}` when its SMTP send throws, and `400` for a request it refuses
    (an unregistered redirect URI, an account with no address). A transport
    error or a timeout lands here too. **None of them starts the cooldown**, so
    a retry can send. A `502` on the route, `invitation: send_failed` on the
    upsert.
    """

    code = "send_failed"


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
    invitation: InvitationOutcome = "not_requested"

    @property
    def invited(self) -> bool:
        return self.invitation == "sent"


@dataclass(frozen=True)
class InvitationResult:
    username: str
    keycloak_id: str
    invitation: InvitationOutcome
    actions: tuple[str, ...]
    lifespan: int


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

    **The one exception is the invitation cooldown**: when each account was last
    sent an email, in memory and per replica. It guards against a double click
    and a repeated upsert, not against abuse — the route is internal-only — and
    losing it on a restart costs at most one extra email.

    **One send rule, whichever call asked** (requester, 2026-09-14: "no spam, do
    not trick the user, if send failed, ok resend"):

    - an email goes out only because a caller asked: the upsert with `invite`,
      or `POST .../invitation`;
    - every send, from either, is refused within the cooldown of the last
      successful send to that account;
    - a send Keycloak did not complete starts no cooldown;
    - an account with a password is never invited, and one without is never
      sent a reset: the route's caller names the email (`intent`) and a
      mismatch is refused before any send or cooldown;
    - an account with no email address is never sent anything (`no_email`).

    The slot is claimed before Keycloak is called and released if nothing went
    out, so two concurrent calls for one account cannot both send.
    """

    def __init__(
        self,
        settings: ProvisioningSettings,
        keycloak_settings: KeycloakSettings,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._keycloak_settings = keycloak_settings
        self._clock = clock
        self._last_sent: dict[str, float] = {}

    # -- the upsert --------------------------------------------------------

    async def ensure_participant(
        self,
        *,
        community: str,
        key: str,
        email: str,
        first_name: str | None = None,
        last_name: str | None = None,
        locale: str | None = None,
        invite: bool = False,
    ) -> UpsertResult:
        """Ensure an account exists for this member and is filed in its REC.

        Idempotent on `(community, key)` in the only sense that matters: a
        second call finds the account the first one made, joins nothing twice,
        and answers `created=False`.

        The REC organization is **ensured, not required**. A community whose
        organization does not exist yet is the ordinary state of a realm that
        has been synced but never swept, and refusing here would make the first
        onboarding of a new REC fail for a reason its operator cannot act on.

        **`invite` sends only to an account created in this call, or one with
        no password**, so a retry on an account whose owner has already set a
        password sends nothing. It never fails the upsert: a disabled account,
        an account that already has a password, one with no email address, one
        emailed within the cooldown, an address outside the dev list, or a send
        Keycloak did not complete comes back as `invitation`, a reason code the
        caller can show the operator who approved.
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
                locale=locale,
            )

            logger.info(
                "Provisioned %s/%s as '%s' (%s)",
                community,
                key,
                participant.username,
                "created" if participant.created else "existing",
            )

            invitation: InvitationOutcome = "not_requested"
            if invite:
                invitation = await self._invite_on_upsert(
                    provisioner,
                    who=f"{community}/{key}",
                    keycloak_id=participant.keycloak_id,
                    created=participant.created,
                    email=email,
                )

            return UpsertResult(
                username=participant.username,
                keycloak_id=participant.keycloak_id,
                created=participant.created,
                invitation=invitation,
            )

    async def _invite_on_upsert(
        self,
        provisioner: Provisioner,
        *,
        who: str,
        keycloak_id: str,
        created: bool,
        email: str,
    ) -> InvitationOutcome:
        """Decide, and send, the invitation an upsert asked for.

        The checks run in the order that sends least and says most: disabled,
        then an existing password (never invited, whatever the cooldown), then
        no address, then the dev list, then the cooldown, which `_send` checks
        as it claims. The address checked is the one Keycloak will send to — the
        account's own. For an account just created that is the body's; for one
        that existed it is what the account carries, **never the body's as a
        stand-in**: Keycloak sends to the account, so an account with no address
        is `no_email` even when the body had one.

        **Nothing here raises for the email's sake.** A cooldown is `cooldown`
        and a failed send is `send_failed`: the account step must not fail on an
        email, and the operator reads the code and can retry.
        """
        address = email
        if not created:
            user = await provisioner.find_by_id(keycloak_id)
            if user is None:
                raise ProvisioningError(f"{who}: account {keycloak_id} vanished")
            if not user.get("enabled", True):
                logger.info("Not inviting %s: the account is disabled", who)
                return "account_disabled"
            if await provisioner.has_password(keycloak_id):
                logger.info("Not inviting %s: the account already has a password", who)
                return "has_password"
            address = user.get("email")

        if not has_address(address):
            logger.info("Not inviting %s: the account has no email address", who)
            return "no_email"

        if not self._settings.email_policy.allows(address):
            self._settings.email_policy.refuse(who)
            return "not_on_dev_list"

        try:
            await self._send(
                provisioner, who, keycloak_id, INVITE_ACTIONS, self._settings.invite_lifespan
            )
        except InvitationCooldown as e:
            logger.info("Not inviting %s: %s", who, e)
            return "cooldown"
        except SendFailed:
            return "send_failed"
        return "sent"

    async def _send(
        self,
        provisioner: Provisioner,
        who: str,
        keycloak_id: str,
        actions: tuple[str, ...],
        lifespan: int,
    ) -> None:
        """The one place an email is sent: check the cooldown, claim it, ask
        Keycloak, and give the slot back if the email did not go out.

        The check and the claim run with no `await` between them, so on one
        event loop a concurrent call for the same account sees the slot taken.
        Raises `InvitationCooldown` or `SendFailed`, never `KeycloakError`.
        """
        remaining = self._cooldown_remaining(keycloak_id)
        if remaining:
            raise InvitationCooldown(
                f"{who} was emailed less than "
                f"{self._settings.invite_cooldown}s ago; try again in {remaining}s",
                retry_after=remaining,
            )
        claimed_at = self._clock()
        self._last_sent[keycloak_id] = claimed_at
        try:
            await provisioner.send_actions_email(
                keycloak_id,
                actions,
                lifespan=lifespan,
                client_id=self._settings.invite_client_id,
                redirect_uri=self._settings.invite_redirect_uri,
            )
        except (KeycloakError, httpx.HTTPError) as e:
            if self._last_sent.get(keycloak_id) == claimed_at:
                del self._last_sent[keycloak_id]
            logger.warning(
                "Keycloak did not email %s (%s); no cooldown started, a retry may send",
                who,
                getattr(e, "status_code", None) or type(e).__name__,
            )
            raise SendFailed(f"Keycloak did not email {who}: {e}") from e
        logger.info("Emailed %s: %s, valid %ss", who, ",".join(actions), lifespan)

    # -- the lifecycle calls ----------------------------------------------

    async def send_invitation(
        self, *, community: str, key: str, intent: SendIntent
    ) -> InvitationResult:
        """Send the email the caller named to a member the registry holds.

        One route, two emails, **chosen by the caller and checked against the
        account** (requester, 2026-09-14, A2: "do not trick the user"):
        `invitation` is `UPDATE_PASSWORD` + `VERIFY_EMAIL` with the invitation
        lifespan, for an account without a password; `password_reset` is
        `UPDATE_PASSWORD` with the reset lifespan, for one that has one. The
        account is read in the same call that sends, so the email can never
        differ from the button a person pressed. **Earlier links are not
        revoked** — Keycloak cannot — so a reset goes out with the short
        lifespan.

        Refuses, in this order: a member the registry does not have
        (`CommunityNotFound`, `MemberNotFound`), a member with no account
        (`AccountNotFound`), a disabled account (`AccountDisabled`), an intent
        the account does not fit (`HasPassword`, `NoPassword`), an account with
        no email address (`NoEmail`), a send within the cooldown of the last one
        to that account, from this route or an upsert (`InvitationCooldown`),
        and a send Keycloak did not complete (`SendFailed`, no cooldown
        started). None before the cooldown starts one. An address outside the
        dev list is not a refusal: it answers `not_on_dev_list`, with nothing
        sent.
        """
        username = await self._username_of(community, key)
        who = f"{community}/{key}"

        async with KeycloakAdminClient(self._keycloak_settings) as kc:
            await kc.authenticate()
            provisioner = Provisioner(kc)

            user = await provisioner.find_by_username(username)
            if not user:
                raise AccountNotFound(
                    f"{who} is registered as '{username}', and the "
                    f"realm has no such account. Provision it first."
                )
            keycloak_id = user["id"]

            if not user.get("enabled", True):
                raise AccountDisabled(
                    f"{who} ('{username}') is disabled; nothing was sent"
                )

            password = await provisioner.has_password(keycloak_id)
            if intent == "invitation":
                if password:
                    raise HasPassword(
                        f"{who} ('{username}') already has a password; no "
                        f"invitation was sent. Send a password reset instead."
                    )
                actions, lifespan = INVITE_ACTIONS, self._settings.invite_lifespan
            elif intent == "password_reset":
                if not password:
                    raise NoPassword(
                        f"{who} ('{username}') has no password to reset; nothing "
                        f"was sent. Send an invitation instead."
                    )
                actions, lifespan = RESET_ACTIONS, self._settings.reset_lifespan
            else:  # the route validates it; a direct caller gets told
                raise ValueError(f"unknown intent {intent!r}")

            if not has_address(user.get("email")):
                raise NoEmail(
                    f"{who} ('{username}') has no email address; nothing was sent"
                )

            outcome: InvitationOutcome
            if self._settings.email_policy.allows(user.get("email")):
                await self._send(provisioner, who, keycloak_id, actions, lifespan)
                outcome = "sent"
            else:
                self._settings.email_policy.refuse(who)
                outcome = "not_on_dev_list"

            return InvitationResult(
                username=username,
                keycloak_id=keycloak_id,
                invitation=outcome,
                actions=actions,
                lifespan=lifespan,
            )

    def _cooldown_remaining(self, keycloak_id: str) -> int:
        """Whole seconds until this account may be emailed again; 0 if it may now.

        Rounded up, so a `Retry-After` honoured to the second is never early.
        """
        last = self._last_sent.get(keycloak_id)
        if last is None:
            return 0
        remaining = self._settings.invite_cooldown - (self._clock() - last)
        return int(remaining) + 1 if remaining > 0 else 0

    async def disable(self, *, community: str, key: str) -> DisableResult:
        """Revoke a member's access without destroying anything."""
        username = await self._username_of(community, key)

        async with KeycloakAdminClient(self._keycloak_settings) as kc:
            await kc.authenticate()
            provisioner = Provisioner(kc)

            user = await provisioner.find_by_username(username)
            if not user:
                raise AccountNotFound(
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
        raise MemberNotFound(f"{community} has no active member '{key}'")

    async def _export(self, community: str) -> dict:
        """The registry's bundle for one community.

        One export per call and no cache. A cache would be state, and the whole
        argument for this service being safe to retry is that it holds none — a
        stale member list is exactly the class of failure this plan exists to
        end.
        """
        if not self._settings.registry_url:
            raise RegistryUnavailable(
                "No registry configured. Set CELINE_PROVISIONING_REGISTRY_URL; "
                "reconcile and the lifecycle calls resolve members through it."
            )
        if not self._settings.registry_client_secret:
            raise RegistryUnavailable(
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
        except RegistryCommunityNotFound as e:
            raise CommunityNotFound(f"The registry has no community '{community}'") from e
        except RegistryError as e:
            raise RegistryUnavailable(str(e)) from e

        if len(documents) != 1:
            # The export is narrowed to one key, so anything else means the
            # registry answered a question nobody asked.
            raise RegistryUnavailable(
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
