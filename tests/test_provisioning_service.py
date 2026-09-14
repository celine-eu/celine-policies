"""What the provisioning service does, with no Keycloak and no registry behind it.

The service is the only writer of participant accounts, so what these cover is
the decisions it makes on the way to a write: which account a call resolves to,
what it refuses, and what it reports when it has provisioned everything and the
realm still disagrees.

**Resolution is asymmetric on purpose and that is most of what is pinned here.**
The upsert has an address and no member row — `../onboarding` writes the row
afterwards, with the username this call returns — so it resolves by email. The
lifecycle calls have a member and no address, and the registry's
`Member.user_id` *is* the username, so they resolve through the registry.

Nothing here talks to a Keycloak or a registry. Both are fakes, so what is
covered is which calls the service decides to make — see the store's
`playbooks/testing.md`.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.provisioning import service as service_module
from celine.provisioning.config import ProvisioningSettings
from celine.policies.cli.keycloak.client import KeycloakError
from celine.provisioning.registry import RegistryCommunityNotFound, RegistryError
from celine.provisioning.service import (
    AccountDisabled,
    AccountNotFound,
    CommunityNotFound,
    HasPassword,
    InvitationCooldown,
    MemberNotFound,
    NoEmail,
    NoPassword,
    ProvisioningError,
    ProvisioningService,
    RegistryUnavailable,
    SendFailed,
)

GREENLAND = {
    "community": {"id": "greenland", "name": "Greenland", "type": "rec"},
    "members": {
        "gl-00001": {"user_id": "gl-00001", "name": "One", "status": "active"},
        "20260912-a3f9c2": {
            "user_id": "a.person@example.org",
            "name": "Two",
            "status": "active",
        },
        "gl-00003": {"user_id": "gl-00003", "name": "Three", "status": "suspended"},
    },
}


class FakeKeycloak:
    """Enough of the Admin API to record what the service decided to do."""

    def __init__(
        self,
        *,
        users_by_email: dict[str, dict] | None = None,
        users_by_username: dict[str, dict] | None = None,
        organization_members: set[tuple[str, str]] | None = None,
        organization_blackhole: bool = False,
        passwords_on: set[str] | None = None,
        send_error: Exception | None = None,
        send_yields: bool = False,
    ):
        self.users_by_email = users_by_email or {}
        self.users_by_username = users_by_username or {}
        self.org_members = organization_members or set()
        #: when set, `ensure_user_in_organization` reports success and the
        #: membership does not stick — the failure the sweep's assertion exists
        #: to catch.
        self.blackhole = organization_blackhole

        #: uuids of the accounts that hold a password credential
        self.passwords_on = passwords_on or set()
        self.send_error = send_error
        #: when set, a send yields to the event loop before it lands, so two
        #: concurrent calls interleave the way two HTTP requests would
        self.send_yields = send_yields
        self.send_attempts = 0

        self.calls: list[tuple] = []
        self.passwords: list[tuple[str, str, bool]] = []
        self.enabled_changes: list[tuple[str, bool]] = []
        self.emails: list[dict] = []
        self.locales: list[tuple[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def authenticate(self):
        self.calls.append(("authenticate",))

    async def ensure_organization(self, *, alias, name, description, attributes):
        self.calls.append(("ensure_organization", alias))
        return f"org-{alias}", False

    async def ensure_org_role(self, org_id, role_name):
        pass

    async def ensure_org_group(self, org_id, name):
        return f"grp-{org_id}-{name}", False

    async def get_user_by_email(self, email):
        self.calls.append(("get_user_by_email", email))
        return self.users_by_email.get(email)

    async def get_user_by_username(self, username):
        self.calls.append(("get_user_by_username", username))
        return self.users_by_username.get(username)

    async def get_user_by_id(self, user_id):
        for user in self.users_by_username.values():
            if user["id"] == user_id:
                return user
        return None

    async def ensure_user(self, username, **kwargs):
        self.calls.append(("ensure_user", username, kwargs))
        if username in self.users_by_username:
            return self.users_by_username[username]["id"], False
        user = {"id": f"uuid-{username}", "username": username, "enabled": True}
        if kwargs.get("email"):
            user["email"] = kwargs["email"]
        if kwargs.get("locale"):
            user["attributes"] = {"locale": [kwargs["locale"]]}
        self.users_by_username[username] = user
        if kwargs.get("email"):
            self.users_by_email[kwargs["email"]] = user
        return user["id"], True

    async def ensure_user_in_organization(self, org_id, user_id):
        self.calls.append(("ensure_user_in_organization", org_id, user_id))
        if not self.blackhole:
            self.org_members.add((org_id, user_id))
        return True

    async def is_user_in_organization(self, org_id, user_id):
        return (org_id, user_id) in self.org_members

    async def ensure_user_in_org_group(self, org_id, group_id, user_id):
        self.calls.append(("ensure_user_in_org_group", org_id, group_id, user_id))

    async def add_user_to_group_with_retry(self, user_id, group_id):
        pass

    async def set_user_password(self, user_id, password, temporary=True):
        self.passwords.append((user_id, password, temporary))

    async def get_user_credentials(self, user_id):
        self.calls.append(("get_user_credentials", user_id))
        return [{"type": "password"}] if user_id in self.passwords_on else []

    async def set_user_locale(self, user_id, locale):
        self.locales.append((user_id, locale))
        return True

    async def execute_actions_email(
        self, user_id, actions, *, lifespan, client_id=None, redirect_uri=None
    ):
        self.send_attempts += 1
        if self.send_yields:
            await asyncio.sleep(0)
        if self.send_error:
            raise self.send_error
        self.emails.append(
            {
                "user_id": user_id,
                "actions": list(actions),
                "lifespan": lifespan,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
            }
        )

    async def set_user_enabled(self, user_id, enabled):
        user = await self.get_user_by_id(user_id)
        if user is None:
            raise AssertionError(f"no such user {user_id}")
        if bool(user.get("enabled")) == enabled:
            return False
        user["enabled"] = enabled
        self.enabled_changes.append((user_id, enabled))
        return True


@pytest.fixture
def keycloak(monkeypatch: pytest.MonkeyPatch):
    """Install a fake admin client and hand it back for inspection."""

    def install(**kwargs) -> FakeKeycloak:
        fake = FakeKeycloak(**kwargs)
        monkeypatch.setattr(
            service_module, "KeycloakAdminClient", lambda *a, **k: fake
        )
        return fake

    return install


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch):
    """Install a fake `GET /admin/export`."""

    def install(documents=None, error: Exception | None = None):
        calls: list[list[str] | None] = []

        async def fake_fetch(*, community_keys=None, **kwargs):
            calls.append(community_keys)
            if error:
                raise error
            return list(documents if documents is not None else [GREENLAND])

        monkeypatch.setattr(service_module, "fetch_rec_documents", fake_fetch)
        return calls

    return install


def a_service(
    *,
    registry_url: str | None = "http://registry",
    clock=None,
    **settings,
) -> ProvisioningService:
    settings.setdefault("email_mode", "deliver")
    settings.setdefault("invite_redirect_uri", "http://webapp.celine.localhost/")
    return ProvisioningService(
        ProvisioningSettings(
            registry_url=registry_url,
            registry_client_id="svc-provisioning",
            registry_client_secret="secret",
            **settings,
        ),
        KeycloakSettings(
            base_url="http://kc.internal",
            realm="celine",
            admin_client_secret="secret",
        ),
        **({"clock": clock} if clock else {}),
    )


class Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


# --- the upsert resolves by address --------------------------------------


async def test_a_new_participant_is_named_after_the_address(keycloak):
    kc = keycloak()

    result = await a_service().ensure_participant(
        community="greenland", key="20260912-a3f9c2", email="A.Person@Example.org"
    )

    assert result.created
    assert result.username == "a.person@example.org"


async def test_an_account_that_already_exists_keeps_the_name_it_has(keycloak):
    """The reason `username` is in the response at all: a participant who signed
    up before either convention authenticates as something nobody here chose,
    and the caller has to store what the account *is* called."""
    legacy = {"id": "uuid-legacy", "username": "gl-00002", "enabled": True}
    kc = keycloak(
        users_by_email={"a.person@example.org": legacy},
        users_by_username={"gl-00002": legacy},
    )

    result = await a_service().ensure_participant(
        community="greenland", key="20260912-a3f9c2", email="a.person@example.org"
    )

    assert result.username == "gl-00002"
    assert result.keycloak_id == "uuid-legacy"
    assert not result.created
    assert "gl-00002" in [c[1] for c in kc.calls if c[0] == "ensure_user"]


async def test_the_upsert_reads_no_registry(keycloak, registry):
    """`../onboarding` writes the member row *after* this call returns, so there
    is nothing to look up. A registry read here would make the first
    provisioning of every participant fail."""
    keycloak()
    calls = registry()

    await a_service().ensure_participant(
        community="greenland", key="20260912-a3f9c2", email="new@example.org"
    )

    assert calls == []


async def test_a_retry_is_the_same_call_and_reports_created_false(keycloak):
    keycloak()
    service = a_service()

    first = await service.ensure_participant(
        community="greenland", key="k", email="p@example.org"
    )
    second = await service.ensure_participant(
        community="greenland", key="k", email="p@example.org"
    )

    assert first.created and not second.created
    assert first.keycloak_id == second.keycloak_id


async def test_the_participant_is_filed_in_the_rec_organization_and_its_group(keycloak):
    kc = keycloak()

    await a_service().ensure_participant(
        community="greenland", key="k", email="p@example.org"
    )

    assert ("ensure_user_in_organization", "org-greenland", "uuid-p@example.org") in kc.calls
    assert (
        "ensure_user_in_org_group",
        "org-greenland",
        "grp-org-greenland-viewers",
        "uuid-p@example.org",
    ) in kc.calls


async def test_the_organization_is_ensured_rather_than_required(keycloak):
    """A REC synced but never swept has no organization yet, and refusing would
    make the first onboarding of a new community fail for a reason its operator
    cannot act on."""
    kc = keycloak()

    await a_service().ensure_participant(
        community="brand-new", key="k", email="p@example.org"
    )

    assert ("ensure_organization", "brand-new") in kc.calls


async def test_the_upsert_writes_the_locale_on_creation(keycloak):
    kc = keycloak()

    await a_service().ensure_participant(
        community="greenland", key="k", email="p@example.org", locale="es"
    )

    [call] = [c for c in kc.calls if c[0] == "ensure_user"]
    assert call[2]["locale"] == "es"


async def test_an_existing_account_gets_a_locale_only_if_it_has_none(keycloak):
    """An account that already carries a locale may carry the person's own
    choice, and an approval is not a reason to overrule it."""
    bare = {"id": "u-bare", "username": "bare@example.org", "enabled": True}
    chosen = {
        "id": "u-chosen",
        "username": "chosen@example.org",
        "enabled": True,
        "attributes": {"locale": ["en"]},
    }
    kc = keycloak(
        users_by_email={"bare@example.org": bare, "chosen@example.org": chosen},
        users_by_username={"bare@example.org": bare, "chosen@example.org": chosen},
    )
    service = a_service()

    await service.ensure_participant(
        community="greenland", key="a", email="bare@example.org", locale="it"
    )
    await service.ensure_participant(
        community="greenland", key="b", email="chosen@example.org", locale="it"
    )

    assert kc.locales == [("u-bare", "it")]


# --- the upsert's invitation ---------------------------------------------


async def test_without_invite_nothing_is_sent_and_nothing_is_checked(keycloak):
    kc = keycloak()

    result = await a_service().ensure_participant(
        community="greenland", key="k", email="p@example.org"
    )

    assert result.invitation == "not_requested"
    assert result.invited is False
    assert kc.emails == []


async def test_an_account_created_by_the_upsert_is_invited(keycloak):
    kc = keycloak()

    result = await a_service().ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert result.created
    assert result.invitation == "sent"
    assert result.invited is True
    assert kc.emails[0]["actions"] == ["UPDATE_PASSWORD", "VERIFY_EMAIL"]
    assert kc.emails[0]["lifespan"] == 604800
    # a new account cannot hold a credential, so it is not asked
    assert ("get_user_credentials", "uuid-p@example.org") not in kc.calls


async def test_an_existing_account_without_a_password_is_invited(keycloak):
    user = {"id": "u1", "username": "p@example.org", "enabled": True, "email": "p@example.org"}
    kc = keycloak(users_by_email={"p@example.org": user}, users_by_username={"p@example.org": user})

    result = await a_service().ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert not result.created
    assert result.invitation == "sent"
    assert len(kc.emails) == 1


async def test_a_retry_on_an_account_that_has_a_password_sends_nothing(keycloak):
    """The retry of onboarding's step after the person has set their password."""
    user = {"id": "u1", "username": "p@example.org", "enabled": True, "email": "p@example.org"}
    kc = keycloak(
        users_by_email={"p@example.org": user},
        users_by_username={"p@example.org": user},
        passwords_on={"u1"},
    )

    result = await a_service().ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert result.invitation == "has_password"
    assert result.invited is False
    assert kc.emails == []


async def test_a_disabled_account_answers_with_the_reason_and_is_not_emailed(keycloak):
    """O3 (requester, 2026-09-14): the upsert does not fail, and it does not
    re-enable the account either."""
    user = {"id": "u1", "username": "p@example.org", "enabled": False, "email": "p@example.org"}
    kc = keycloak(users_by_email={"p@example.org": user}, users_by_username={"p@example.org": user})

    result = await a_service().ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert result.invitation == "account_disabled"
    assert kc.emails == []
    assert kc.enabled_changes == []


async def test_in_dev_mode_an_address_off_the_list_makes_no_keycloak_send(
    keycloak, caplog
):
    kc = keycloak()

    with caplog.at_level("WARNING"):
        result = await a_service(email_mode="dev").ensure_participant(
            community="greenland", key="k", email="p@example.org", invite=True
        )

    assert result.invitation == "not_on_dev_list"
    assert result.invited is False
    assert kc.emails == []
    assert "greenland/k" in caplog.text


async def test_in_dev_mode_an_address_on_the_list_is_invited(keycloak):
    kc = keycloak()

    result = await a_service(
        email_mode="dev", email_dev_recipients=" Someone@Example.org, p@example.org "
    ).ensure_participant(
        community="greenland", key="k", email="P@example.org", invite=True
    )

    assert result.invitation == "sent"
    assert len(kc.emails) == 1


@pytest.mark.parametrize(
    "mode", [{"email_mode": "deliver"}, {"email_mode": "dev", "email_dev_recipients": "p@example.org"}],
    ids=["deliver", "dev-listed"],
)
async def test_an_existing_account_with_no_address_is_no_email_whatever_the_mode(
    keycloak, mode
):
    """N1 (requester, 2026-09-14: "No mail for them"). An account `sync-users`
    made from the registry has no address. It used to read `not_on_dev_list`,
    which is false in `deliver` mode. The body's address is not a stand-in:
    Keycloak sends to the account, and would refuse with `User email missing`."""
    bare = {"id": "u1", "username": "p@example.org", "enabled": True}
    kc = keycloak(users_by_username={"p@example.org": bare})

    result = await a_service(clock=Clock(), **mode).ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert not result.created
    assert result.invitation == "no_email"
    assert result.invited is False
    assert kc.send_attempts == 0


async def test_no_email_comes_before_the_dev_list(keycloak):
    bare = {"id": "u1", "username": "p@example.org", "enabled": True, "email": " "}
    kc = keycloak(users_by_username={"p@example.org": bare})

    result = await a_service(email_mode="dev").ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert result.invitation == "no_email"
    assert kc.send_attempts == 0


async def test_an_account_with_a_password_and_no_address_is_has_password(keycloak):
    """The existing order holds: a password means nothing to invite to."""
    bare = {"id": "u1", "username": "p@example.org", "enabled": True}
    kc = keycloak(users_by_username={"p@example.org": bare}, passwords_on={"u1"})

    result = await a_service().ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert result.invitation == "has_password"
    assert kc.send_attempts == 0


async def test_the_email_mode_defaults_to_dev(keycloak):
    """Its failure is an invitation that did not go out and says so; the other
    default's is emailing real people from a debugging session."""
    assert ProvisioningSettings().email_mode == "dev"


# --- one send rule for the upsert and the route ---------------------------


def _existing(uuid="u1", email="p@example.org", *, enabled=True):
    user = {"id": uuid, "username": email, "enabled": enabled, "email": email}
    return {"users_by_email": {email: user}, "users_by_username": {email: user}}


async def test_a_repeated_upsert_within_the_cooldown_sends_once_and_says_cooldown(keycloak):
    """Before 2026-09-14 the cooldown guarded only the route, so every repeated
    upsert on an account without a password sent another email. The requester:
    "no spam". The upsert still succeeds: the account step must not fail on an
    email."""
    kc = keycloak(**_existing())
    clock = Clock()
    service = a_service(clock=clock)

    first = await service.ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )
    clock.now += 60
    second = await service.ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert first.invitation == "sent"
    assert second.invitation == "cooldown"
    assert second.invited is False
    assert second.keycloak_id == first.keycloak_id
    assert len(kc.emails) == 1


async def test_an_upsert_after_the_cooldown_sends_again(keycloak):
    """The account still has no password, so a caller who asks again after the
    cooldown gets another invitation — the rule is a bound, not a ban."""
    kc = keycloak(**_existing())
    clock = Clock()
    service = a_service(clock=clock)

    await service.ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )
    clock.now += 300
    again = await service.ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert again.invitation == "sent"
    assert len(kc.emails) == 2


async def test_a_route_send_puts_a_following_upsert_in_the_cooldown(keycloak, registry):
    """The same cooldown whichever call sent first."""
    kc = keycloak(**_existing())
    registry(
        documents=[
            {
                **GREENLAND,
                "members": {"k": {"user_id": "p@example.org", "name": "P", "status": "active"}},
            }
        ]
    )
    service = a_service(clock=Clock())

    await service.send_invitation(community="greenland", key="k", intent="invitation")
    result = await service.ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert result.invitation == "cooldown"
    assert len(kc.emails) == 1


async def test_an_account_with_a_password_is_has_password_even_within_the_cooldown(
    keycloak, registry
):
    """The upsert never invites an account with a password, and says so rather
    than blaming the clock."""
    kc = keycloak(**_existing(), passwords_on={"u1"})
    registry(
        documents=[
            {
                **GREENLAND,
                "members": {"k": {"user_id": "p@example.org", "name": "P", "status": "active"}},
            }
        ]
    )
    service = a_service(clock=Clock())

    await service.send_invitation(community="greenland", key="k", intent="password_reset")
    result = await service.ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert result.invitation == "has_password"
    assert len(kc.emails) == 1


@pytest.mark.parametrize(
    "error",
    [
        KeycloakError(
            'Unexpected response 500: {"errorMessage":"Failed to send execute actions email: '
            'Error when attempting to send the email to the server."}',
            status_code=500,
        ),
        httpx.ReadTimeout("timed out"),
    ],
    ids=["smtp-500", "timeout"],
)
async def test_an_upsert_whose_send_failed_succeeds_with_send_failed_and_starts_no_cooldown(
    keycloak, error
):
    """"If send failed, ok resend" (requester, 2026-09-14). Keycloak answers
    `500 Failed to send execute actions email` when SMTP throws. The account
    step succeeds, the operator reads `send_failed`, and a retry sends."""
    kc = keycloak(**_existing(), send_error=error)
    service = a_service(clock=Clock())

    failed = await service.ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )
    kc.send_error = None
    retried = await service.ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert failed.invitation == "send_failed"
    assert failed.invited is False
    assert retried.invitation == "sent"
    assert len(kc.emails) == 1


async def test_a_new_account_whose_send_failed_is_still_created(keycloak):
    kc = keycloak(send_error=KeycloakError("Unexpected response 500", status_code=500))

    result = await a_service().ensure_participant(
        community="greenland", key="k", email="new@example.org", invite=True
    )

    assert result.created
    assert result.invitation == "send_failed"
    assert "new@example.org" in kc.users_by_email


async def test_a_failed_route_send_lets_the_next_upsert_send(keycloak, registry):
    kc = keycloak(**_existing(), send_error=KeycloakError("500", status_code=500))
    registry(
        documents=[
            {
                **GREENLAND,
                "members": {"k": {"user_id": "p@example.org", "name": "P", "status": "active"}},
            }
        ]
    )
    service = a_service(clock=Clock())

    with pytest.raises(SendFailed):
        await service.send_invitation(community="greenland", key="k", intent="invitation")
    kc.send_error = None
    result = await service.ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )

    assert result.invitation == "sent"
    assert len(kc.emails) == 1


async def test_two_concurrent_upserts_for_one_account_send_one_email(keycloak):
    """The slot is claimed before Keycloak is called, so the second call sees it
    while the first is still waiting on the send."""
    kc = keycloak(**_existing(), send_yields=True)
    service = a_service(clock=Clock())

    results = await asyncio.gather(
        *(
            service.ensure_participant(
                community="greenland", key="k", email="p@example.org", invite=True
            )
            for _ in range(2)
        )
    )

    assert sorted(r.invitation for r in results) == ["cooldown", "sent"]
    assert kc.send_attempts == 1
    assert len(kc.emails) == 1


async def test_a_cooldown_of_zero_never_refuses(keycloak):
    kc = keycloak(**_existing())
    service = a_service(clock=Clock(), invite_cooldown=0)

    for _ in range(2):
        result = await service.ensure_participant(
            community="greenland", key="k", email="p@example.org", invite=True
        )
        assert result.invitation == "sent"

    assert len(kc.emails) == 2


# --- the lifecycle calls resolve through the registry --------------------


def _member(uuid="u1", username="gl-00001", *, enabled=True, email="one@example.org"):
    user = {"id": uuid, "username": username, "enabled": enabled}
    if email is not None:
        user["email"] = email
    return {username: user}


def _intent(call: str) -> dict:
    return {"intent": "invitation"} if call == "send_invitation" else {}


async def test_an_invitation_finds_the_member_by_its_registry_row(keycloak, registry):
    kc = keycloak(
        users_by_username=_member("uuid-legacy", "a.person@example.org", email="a.person@example.org")
    )
    registry()

    result = await a_service().send_invitation(
        community="greenland", key="20260912-a3f9c2", intent="invitation"
    )

    assert result.username == "a.person@example.org"
    assert result.invitation == "sent"
    assert [e["user_id"] for e in kc.emails] == ["uuid-legacy"]


async def test_an_account_without_a_password_is_invited_for_seven_days(keycloak, registry):
    kc = keycloak(users_by_username=_member())
    registry()

    result = await a_service().send_invitation(community="greenland", key="gl-00001", intent="invitation")

    assert result.actions == ("UPDATE_PASSWORD", "VERIFY_EMAIL")
    assert result.lifespan == 604800
    assert kc.emails == [
        {
            "user_id": "u1",
            "actions": ["UPDATE_PASSWORD", "VERIFY_EMAIL"],
            "lifespan": 604800,
            "client_id": "oauth2_proxy",
            "redirect_uri": "http://webapp.celine.localhost/",
        }
    ]


async def test_an_account_with_a_password_gets_a_one_hour_reset(keycloak, registry):
    """O2 (requester, 2026-09-14). Earlier links are not revoked by Keycloak,
    so a reset email must not be a 7-day credential."""
    kc = keycloak(users_by_username=_member(), passwords_on={"u1"})
    registry()

    result = await a_service().send_invitation(
        community="greenland", key="gl-00001", intent="password_reset"
    )

    assert result.actions == ("UPDATE_PASSWORD",)
    assert result.lifespan == 3600
    assert kc.emails[0]["actions"] == ["UPDATE_PASSWORD"]
    assert kc.emails[0]["lifespan"] == 3600


async def test_an_invitation_to_an_account_with_a_password_is_refused_before_any_send(
    keycloak, registry
):
    """A2 (requester, 2026-09-14: "do not trick the user"). Not turned into a
    reset, and no cooldown started, so the other button works at once."""
    kc = keycloak(users_by_username=_member(), passwords_on={"u1"})
    registry()
    service = a_service(clock=Clock())

    with pytest.raises(HasPassword) as excinfo:
        await service.send_invitation(community="greenland", key="gl-00001", intent="invitation")

    assert excinfo.value.code == "has_password"
    assert kc.send_attempts == 0

    result = await service.send_invitation(
        community="greenland", key="gl-00001", intent="password_reset"
    )
    assert result.actions == ("UPDATE_PASSWORD",)
    assert len(kc.emails) == 1


async def test_a_reset_of_an_account_without_a_password_is_refused_before_any_send(
    keycloak, registry
):
    """Never silently turned into an invitation (A2), and no cooldown started."""
    kc = keycloak(users_by_username=_member())
    registry()
    service = a_service(clock=Clock())

    with pytest.raises(NoPassword) as excinfo:
        await service.send_invitation(
            community="greenland", key="gl-00001", intent="password_reset"
        )

    assert excinfo.value.code == "no_password"
    assert kc.send_attempts == 0

    result = await service.send_invitation(
        community="greenland", key="gl-00001", intent="invitation"
    )
    assert result.actions == ("UPDATE_PASSWORD", "VERIFY_EMAIL")
    assert len(kc.emails) == 1


async def test_a_mismatch_is_reported_as_such_even_within_the_cooldown(keycloak, registry):
    """The mismatch comes before the cooldown: the person is told to use the
    other button, not to wait for a clock."""
    kc = keycloak(users_by_username=_member(), passwords_on={"u1"})
    registry()
    service = a_service(clock=Clock())

    await service.send_invitation(community="greenland", key="gl-00001", intent="password_reset")
    with pytest.raises(HasPassword):
        await service.send_invitation(community="greenland", key="gl-00001", intent="invitation")

    assert len(kc.emails) == 1


async def test_a_disabled_account_is_account_disabled_whatever_the_intent(keycloak, registry):
    kc = keycloak(users_by_username=_member(enabled=False), passwords_on={"u1"})
    registry()

    for intent in ("invitation", "password_reset"):
        with pytest.raises(AccountDisabled):
            await a_service().send_invitation(
                community="greenland", key="gl-00001", intent=intent
            )

    assert kc.send_attempts == 0


@pytest.mark.parametrize(
    "mode",
    [{"email_mode": "deliver"}, {"email_mode": "dev"}],
    ids=["deliver", "dev"],
)
@pytest.mark.parametrize("intent,passwords", [("invitation", set()), ("password_reset", {"u1"})])
async def test_an_account_with_no_address_is_no_email_whatever_the_mode(
    keycloak, registry, mode, intent, passwords
):
    """N1 (requester, 2026-09-14: "No mail for them"). Before the dev list, so
    `dev` mode does not answer `not_on_dev_list` for it."""
    kc = keycloak(users_by_username=_member(email=None), passwords_on=passwords)
    registry()

    with pytest.raises(NoEmail) as excinfo:
        await a_service(clock=Clock(), **mode).send_invitation(
            community="greenland", key="gl-00001", intent=intent
        )

    assert excinfo.value.code == "no_email"
    assert kc.send_attempts == 0


async def test_an_intent_mismatch_is_reported_before_a_missing_address(keycloak, registry):
    """The same order as the upsert: the password, then the address."""
    keycloak(users_by_username=_member(email=None), passwords_on={"u1"})
    registry()

    with pytest.raises(HasPassword):
        await a_service().send_invitation(community="greenland", key="gl-00001", intent="invitation")


async def test_an_unknown_intent_from_a_direct_caller_sends_nothing(keycloak, registry):
    kc = keycloak(users_by_username=_member())
    registry()

    with pytest.raises(ValueError):
        await a_service().send_invitation(community="greenland", key="gl-00001", intent="reset")

    assert kc.send_attempts == 0


async def test_no_password_is_generated_or_set_by_an_invitation(keycloak, registry):
    kc = keycloak(users_by_username=_member())
    registry()

    result = await a_service().send_invitation(community="greenland", key="gl-00001", intent="invitation")

    assert kc.passwords == []
    assert not hasattr(result, "password")


async def test_an_invitation_to_a_disabled_account_is_refused_before_keycloak_is_asked(
    keycloak, registry
):
    kc = keycloak(users_by_username=_member(enabled=False))
    registry()

    with pytest.raises(AccountDisabled):
        await a_service().send_invitation(community="greenland", key="gl-00001", intent="invitation")

    assert kc.emails == []


async def test_a_second_invitation_within_the_cooldown_is_refused(keycloak, registry):
    kc = keycloak(users_by_username=_member())
    registry()
    clock = Clock()
    service = a_service(clock=clock)

    await service.send_invitation(community="greenland", key="gl-00001", intent="invitation")
    clock.now += 60
    with pytest.raises(InvitationCooldown) as excinfo:
        await service.send_invitation(community="greenland", key="gl-00001", intent="invitation")

    assert excinfo.value.retry_after == 241
    assert len(kc.emails) == 1

    clock.now += 241
    await service.send_invitation(community="greenland", key="gl-00001", intent="invitation")
    assert len(kc.emails) == 2


async def test_an_upsert_invitation_starts_the_cooldown_too(keycloak, registry):
    kc = keycloak()
    registry(
        documents=[
            {
                **GREENLAND,
                "members": {
                    "k": {"user_id": "p@example.org", "name": "P", "status": "active"}
                },
            }
        ]
    )
    service = a_service(clock=Clock())

    await service.ensure_participant(
        community="greenland", key="k", email="p@example.org", invite=True
    )
    with pytest.raises(InvitationCooldown):
        await service.send_invitation(community="greenland", key="k", intent="invitation")

    assert len(kc.emails) == 1


async def test_in_dev_mode_an_address_off_the_list_is_not_emailed_and_is_logged(
    keycloak, registry, caplog
):
    kc = keycloak(users_by_username=_member(email="someone@example.org"))
    registry()

    with caplog.at_level("WARNING"):
        result = await a_service(
            email_mode="dev", email_dev_recipients="allowed@example.org"
        ).send_invitation(community="greenland", key="gl-00001", intent="invitation")

    assert result.invitation == "not_on_dev_list"
    assert kc.emails == []
    assert "greenland/gl-00001" in caplog.text
    assert "someone@example.org" not in caplog.text


async def test_a_keycloak_refusal_to_send_is_send_failed(keycloak, registry):
    """An unregistered redirect URI is Keycloak's 400; it is a dependency
    failing, and it must not start the cooldown."""
    kc = keycloak(
        users_by_username=_member(),
        send_error=KeycloakError("Unexpected response 400: Invalid redirect uri."),
    )
    registry()
    service = a_service(clock=Clock())

    with pytest.raises(SendFailed) as excinfo:
        await service.send_invitation(community="greenland", key="gl-00001", intent="invitation")
    assert excinfo.value.code == "send_failed"

    kc.send_error = None
    await service.send_invitation(community="greenland", key="gl-00001", intent="invitation")
    assert len(kc.emails) == 1


async def test_disabling_revokes_without_deleting(keycloak, registry):
    kc = keycloak(
        users_by_username={"gl-00001": {"id": "u1", "username": "gl-00001", "enabled": True}}
    )
    registry()

    result = await a_service().disable(community="greenland", key="gl-00001")

    assert result.changed
    assert kc.enabled_changes == [("u1", False)]
    assert "gl-00001" in kc.users_by_username  # nothing was deleted


async def test_disabling_twice_reports_no_change(keycloak, registry):
    """A revocation already in force must not read as one that just happened."""
    keycloak(
        users_by_username={"gl-00001": {"id": "u1", "username": "gl-00001", "enabled": False}}
    )
    registry()

    result = await a_service().disable(community="greenland", key="gl-00001")

    assert not result.changed


@pytest.mark.parametrize("call", ["send_invitation", "disable"])
async def test_a_key_the_registry_does_not_hold_is_member_not_found(
    keycloak, registry, call
):
    keycloak()
    registry()

    with pytest.raises(MemberNotFound) as excinfo:
        await getattr(a_service(), call)(community="greenland", key="nobody", **_intent(call))

    assert excinfo.value.code == "member_not_found"
    assert "nobody" in str(excinfo.value)


async def test_a_suspended_member_is_member_not_found(keycloak, registry):
    """The export carries every member; only `active` ones resolve."""
    keycloak(users_by_username=_member("u3", "gl-00003"))
    registry()

    with pytest.raises(MemberNotFound):
        await a_service().send_invitation(community="greenland", key="gl-00003", intent="invitation")


@pytest.mark.parametrize("call", ["send_invitation", "disable"])
async def test_a_member_with_no_account_is_account_not_found_and_says_what_it_looked_for(
    keycloak, registry, call
):
    """The registry has the member, the realm has no account: a different
    thing to fix (provision it) from a member nobody has."""
    keycloak()
    registry()

    with pytest.raises(AccountNotFound) as excinfo:
        await getattr(a_service(), call)(community="greenland", key="gl-00001", **_intent(call))

    assert not isinstance(excinfo.value, MemberNotFound)
    assert excinfo.value.code == "account_not_found"
    assert "gl-00001" in str(excinfo.value)


@pytest.mark.parametrize("call", ["send_invitation", "disable", "reconcile"])
async def test_a_community_the_registry_does_not_have_is_community_not_found(
    keycloak, registry, call
):
    kc = keycloak()
    registry(error=RegistryCommunityNotFound("http://registry has no community nowhere"))
    service = a_service()

    with pytest.raises(CommunityNotFound) as excinfo:
        if call == "reconcile":
            await service.reconcile("nowhere")
        else:
            await getattr(service, call)(community="nowhere", key="gl-00001", **_intent(call))

    assert excinfo.value.code == "community_not_found"
    assert "nowhere" in str(excinfo.value)
    assert kc.calls == []


async def test_a_registry_that_cannot_be_read_is_registry_unavailable(keycloak, registry):
    """Not a 404: an outage must not read as "nobody here"."""
    keycloak()
    registry(error=RegistryError("Could not export: 401"))

    with pytest.raises(RegistryUnavailable) as excinfo:
        await a_service().disable(community="greenland", key="gl-00001")

    assert excinfo.value.code == "registry_unavailable"


async def test_no_registry_configured_refuses_with_the_variable_named(keycloak):
    keycloak()

    with pytest.raises(RegistryUnavailable) as excinfo:
        await a_service(registry_url=None).send_invitation(
            community="greenland", key="gl-00001", intent="invitation"
        )

    assert "CELINE_PROVISIONING_REGISTRY_URL" in str(excinfo.value)


# --- the sweep ------------------------------------------------------------


async def test_the_sweep_provisions_every_active_member_and_skips_the_rest(
    keycloak, registry
):
    """A suspended member is skipped and **not** disabled: skipping provisioning
    and revoking access are different acts with different owners."""
    kc = keycloak()
    registry()

    result = await a_service().reconcile("greenland")

    assert result.members == 2
    assert result.created == 2
    provisioned = [c[1] for c in kc.calls if c[0] == "ensure_user"]
    assert provisioned == ["gl-00001", "a.person@example.org"]
    assert kc.enabled_changes == []


async def test_the_sweep_names_the_member_after_its_registry_row(keycloak, registry):
    """`user_id` and `key` disagree for anybody onboarding provisioned, and the
    row is what owns the username — deriving from the key would make a second
    account beside the one they already sign in with."""
    kc = keycloak()
    registry()

    await a_service().reconcile("greenland")

    assert "20260912-a3f9c2" not in [c[1] for c in kc.calls if c[0] == "ensure_user"]


async def test_the_sweep_creates_no_credential(keycloak, registry):
    """A member the sweep creates is one nobody has been handed anything for.
    Inventing a password produces a secret that exists, grants access and was
    never given to anybody."""
    kc = keycloak()
    registry()

    await a_service().reconcile("greenland")

    assert all(
        call[2]["temporary_password"] is None
        for call in kc.calls
        if call[0] == "ensure_user"
    )
    assert kc.passwords == []


async def test_a_healthy_sweep_finds_no_divergence(keycloak, registry):
    keycloak()
    registry()

    result = await a_service().reconcile("greenland")

    assert result.divergences == ()


async def test_the_sweep_reports_a_membership_that_did_not_stick(keycloak, registry):
    """The assertion `a-grant-can-name-one-organization` owed. Everything it
    checks is something this same call claimed to have done, so a finding is a
    provisioning call that reported success and had not succeeded."""
    keycloak(organization_blackhole=True)
    registry()

    result = await a_service().reconcile("greenland")

    assert len(result.divergences) == 2
    assert {d.kind for d in result.divergences} == {"not in the REC organization"}
    assert {d.key for d in result.divergences} == {"gl-00001", "20260912-a3f9c2"}


async def test_the_sweep_narrows_the_export_to_the_community_it_was_asked_about(
    keycloak, registry
):
    keycloak()
    calls = registry()

    await a_service().reconcile("greenland")

    assert calls == [["greenland"]]


async def test_more_than_one_document_for_one_community_is_refused(keycloak, registry):
    """The export was narrowed to one key, so anything else means the registry
    answered a question nobody asked."""
    keycloak()
    registry(documents=[GREENLAND, GREENLAND])

    with pytest.raises(ProvisioningError):
        await a_service().reconcile("greenland")
