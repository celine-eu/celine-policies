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
from celine.policies.cli.keycloak.client import KeycloakConflictError, KeycloakError
from celine.provisioning.registry import RegistryCommunityNotFound, RegistryError
from celine.provisioning.service import (
    AccountDisabled,
    AccountNotFound,
    CommunityNotFound,
    EmailTaken,
    HasPassword,
    InvitationCooldown,
    ManagedMember,
    MemberNotFound,
    MemberOfAnotherCommunity,
    NoEmail,
    NoPassword,
    ProvisioningError,
    ProvisioningService,
    RegistryUnavailable,
    SendFailed,
)

EXAMPLE_REC = {
    "community": {"id": "example-rec", "name": "Example REC", "type": "rec"},
    "members": {
        "ex-00001": {"user_id": "ex-00001", "name": "One", "status": "active"},
        "20260912-a3f9c2": {
            "user_id": "a.person@example.org",
            "name": "Two",
            "status": "active",
        },
        "ex-00003": {"user_id": "ex-00003", "name": "Three", "status": "suspended"},
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
        org_group_members: set[tuple[str, str, str]] | None = None,
        organization_blackhole: bool = False,
        passwords_on: set[str] | None = None,
        send_error: Exception | None = None,
        send_yields: bool = False,
        update_error: Exception | None = None,
        org_types: dict[str, str] | None = None,
        managed: set[tuple[str, str]] | None = None,
    ):
        self.users_by_email = users_by_email or {}
        self.users_by_username = users_by_username or {}
        self.org_members = organization_members or set()
        #: (org_id, group_id, user_id). Removed only by a release.
        self.org_group_members = org_group_members or set()
        #: alias -> type, for organizations that exist before the call;
        #: `ensure_organization` adds its own as a REC.
        self.org_types: dict[str, str] = dict(org_types or {})
        #: (org_id, user_id) of MANAGED memberships
        self.managed = managed or set()
        self.logouts: list[str] = []
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
        self.update_error = update_error

        self.calls: list[tuple] = []
        self.passwords: list[tuple[str, str, bool]] = []
        self.enabled_changes: list[tuple[str, bool]] = []
        self.emails: list[dict] = []
        #: the address the account carried when each email went out, which is
        #: where Keycloak sends it
        self.sent_to: list[str | None] = []
        #: `send-verify-email` calls, kept apart from the actions emails
        self.verifications: list[dict] = []
        self.locales: list[tuple[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def authenticate(self):
        self.calls.append(("authenticate",))

    async def ensure_organization(self, *, alias, name, description, attributes):
        self.calls.append(("ensure_organization", alias))
        self.org_types.setdefault(alias, (attributes or {}).get("type", ["rec"])[0])
        return f"org-{alias}", False

    async def get_organization_by_alias(self, alias):
        if alias not in self.org_types:
            return None
        return {"id": f"org-{alias}", "alias": alias}

    async def get_user_organizations(self, user_id):
        self.calls.append(("get_user_organizations", user_id))
        return [
            {"id": org, "alias": org.removeprefix("org-"),
             "attributes": {"type": [self.org_types.get(org.removeprefix("org-"), "rec")]}}
            for org, uid in sorted(self.org_members)
            if uid == user_id
        ]

    async def get_organization_member(self, org_id, user_id):
        if (org_id, user_id) not in self.org_members:
            return None
        kind = "MANAGED" if (org_id, user_id) in self.managed else "UNMANAGED"
        return {"id": user_id, "membershipType": kind}

    async def get_member_org_groups(self, org_id, user_id):
        return [
            {"id": gid, "name": gid.rsplit("-", 1)[-1]}
            for org, gid, uid in sorted(self.org_group_members)
            if org == org_id and uid == user_id
        ]

    async def remove_user_from_org_group(self, org_id, group_id, user_id):
        self.calls.append(("remove_user_from_org_group", org_id, group_id, user_id))
        if (org_id, group_id, user_id) not in self.org_group_members:
            return False
        self.org_group_members.discard((org_id, group_id, user_id))
        return True

    async def remove_user_from_organization(self, org_id, user_id):
        self.calls.append(("remove_user_from_organization", org_id, user_id))
        if (org_id, user_id) not in self.org_members:
            return False
        self.org_members.discard((org_id, user_id))
        # Keycloak drops the org groups with the membership.
        self.org_group_members = {
            m for m in self.org_group_members if not (m[0] == org_id and m[2] == user_id)
        }
        return True

    async def logout_user(self, user_id):
        self.calls.append(("logout_user", user_id))
        self.logouts.append(user_id)

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
        if (org_id, user_id) in self.org_members:
            return False
        if not self.blackhole:
            self.org_members.add((org_id, user_id))
        return True

    async def is_user_in_organization(self, org_id, user_id):
        return (org_id, user_id) in self.org_members

    async def ensure_user_in_org_group(self, org_id, group_id, user_id):
        self.calls.append(("ensure_user_in_org_group", org_id, group_id, user_id))
        self.org_group_members.add((org_id, group_id, user_id))

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
        self.sent_to.append(((await self.get_user_by_id(user_id)) or {}).get("email"))
        self.emails.append(
            {
                "user_id": user_id,
                "actions": list(actions),
                "lifespan": lifespan,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
            }
        )

    async def get_users_by_email(self, email):
        self.calls.append(("get_users_by_email", email))
        wanted = email.strip().lower()
        seen = {}
        for user in [*self.users_by_username.values(), *self.users_by_email.values()]:
            if (user.get("email") or "").strip().lower() == wanted:
                seen[user["id"]] = user
        return list(seen.values())

    async def update_user_profile(
        self, user_id, *, first_name=None, last_name=None, email=None, email_verified=None
    ):
        self.calls.append(
            ("update_user_profile", user_id, first_name, last_name, email, email_verified)
        )
        if self.update_error:
            raise self.update_error
        user = await self.get_user_by_id(user_id)
        for name, value in (
            ("firstName", first_name),
            ("lastName", last_name),
            ("email", email),
            ("emailVerified", email_verified),
        ):
            if value is not None:
                user[name] = value
        return dict(user)

    async def put_user(self, user_id, representation):
        self.calls.append(("put_user", user_id))
        user = await self.get_user_by_id(user_id)
        user.clear()
        user.update(representation)

    async def send_verify_email(self, user_id, *, lifespan, client_id=None, redirect_uri=None):
        """`send-verify-email`: Keycloak's own verification email, which the
        theme renders with `email-verification.ftl`, never as an invitation."""
        self.send_attempts += 1
        if self.send_error:
            raise self.send_error
        self.sent_to.append(((await self.get_user_by_id(user_id)) or {}).get("email"))
        self.verifications.append(
            {
                "user_id": user_id,
                "lifespan": lifespan,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
            }
        )

    async def set_user_enabled(self, user_id, enabled):
        self.calls.append(("set_user_enabled", user_id, enabled))
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
            return list(documents if documents is not None else [EXAMPLE_REC])

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
        community="example-rec", key="20260912-a3f9c2", email="A.Person@Example.org"
    )

    assert result.created
    assert result.username == "a.person@example.org"


async def test_an_account_that_already_exists_keeps_the_name_it_has(keycloak):
    """The reason `username` is in the response at all: a participant who signed
    up before either convention authenticates as something nobody here chose,
    and the caller has to store what the account *is* called."""
    legacy = {"id": "uuid-legacy", "username": "ex-00002", "enabled": True}
    kc = keycloak(
        users_by_email={"a.person@example.org": legacy},
        users_by_username={"ex-00002": legacy},
    )

    result = await a_service().ensure_participant(
        community="example-rec", key="20260912-a3f9c2", email="a.person@example.org"
    )

    assert result.username == "ex-00002"
    assert result.keycloak_id == "uuid-legacy"
    assert not result.created
    assert "ex-00002" in [c[1] for c in kc.calls if c[0] == "ensure_user"]


async def test_the_upsert_reads_no_registry(keycloak, registry):
    """`../onboarding` writes the member row *after* this call returns, so there
    is nothing to look up. A registry read here would make the first
    provisioning of every participant fail."""
    keycloak()
    calls = registry()

    await a_service().ensure_participant(
        community="example-rec", key="20260912-a3f9c2", email="new@example.org"
    )

    assert calls == []


async def test_a_retry_is_the_same_call_and_reports_created_false(keycloak):
    keycloak()
    service = a_service()

    first = await service.ensure_participant(
        community="example-rec", key="k", email="p@example.org"
    )
    second = await service.ensure_participant(
        community="example-rec", key="k", email="p@example.org"
    )

    assert first.created and not second.created
    assert first.keycloak_id == second.keycloak_id


async def test_the_participant_is_filed_in_the_rec_organization_and_its_group(keycloak):
    kc = keycloak()

    await a_service().ensure_participant(
        community="example-rec", key="k", email="p@example.org"
    )

    assert ("ensure_user_in_organization", "org-example-rec", "uuid-p@example.org") in kc.calls
    assert (
        "ensure_user_in_org_group",
        "org-example-rec",
        "grp-org-example-rec-viewers",
        "uuid-p@example.org",
    ) in kc.calls


async def test_filing_a_manager_as_a_participant_keeps_their_managers_membership(
    keycloak,
):
    """A manager who is also a participant onboards with the address their
    manager account carries; approval adopts that account and adds `viewers`.
    Losing `managers` would lock them out of their own dashboard.

    @verifies REQ-0003
    """
    manager = {
        "id": "uuid-manager",
        "username": "manager@example.org",
        "email": "manager@example.org",
        "enabled": True,
    }
    managers = ("org-example-rec", "grp-org-example-rec-managers", "uuid-manager")
    admins_elsewhere = ("org-example-dso", "grp-org-example-dso-admins", "uuid-manager")
    kc = keycloak(
        users_by_email={"manager@example.org": manager},
        users_by_username={"manager@example.org": manager},
        organization_members={("org-example-rec", "uuid-manager")},
        org_group_members={managers, admins_elsewhere},
    )

    result = await a_service().ensure_participant(
        community="example-rec", key="ex-00001", email="manager@example.org"
    )

    assert not result.created
    assert result.keycloak_id == "uuid-manager"
    assert kc.org_group_members == {
        managers,
        admins_elsewhere,
        ("org-example-rec", "grp-org-example-rec-viewers", "uuid-manager"),
    }
    # Only additive calls were made: nothing that leaves, removes or deletes.
    assert not [
        c
        for c in kc.calls
        if any(word in c[0] for word in ("remove", "leave", "delete"))
    ]


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
        community="example-rec", key="k", email="p@example.org", locale="es"
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
        community="example-rec", key="a", email="bare@example.org", locale="it"
    )
    await service.ensure_participant(
        community="example-rec", key="b", email="chosen@example.org", locale="it"
    )

    assert kc.locales == [("u-bare", "it")]


# --- the upsert's invitation ---------------------------------------------


async def test_without_invite_nothing_is_sent_and_nothing_is_checked(keycloak):
    kc = keycloak()

    result = await a_service().ensure_participant(
        community="example-rec", key="k", email="p@example.org"
    )

    assert result.invitation == "not_requested"
    assert result.invited is False
    assert kc.emails == []


async def test_an_account_created_by_the_upsert_is_invited(keycloak):
    kc = keycloak()

    result = await a_service().ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
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
        community="example-rec", key="k", email="p@example.org", invite=True
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
        community="example-rec", key="k", email="p@example.org", invite=True
    )

    assert result.invitation == "has_password"
    assert result.invited is False
    assert kc.emails == []


async def test_a_disabled_account_answers_with_the_reason_and_is_not_emailed(keycloak):
    """O3 (requester, 2026-09-14): the upsert does not fail, and it does not
    re-enable an account disabled while it is in the community's organization
    (an older revocation, an operator's lock). A released account, outside
    every REC, is the other case: see the re-enable tests below."""
    user = {"id": "u1", "username": "p@example.org", "enabled": False, "email": "p@example.org"}
    kc = keycloak(
        users_by_email={"p@example.org": user},
        users_by_username={"p@example.org": user},
        organization_members={("org-example-rec", "u1")},
    )

    result = await a_service().ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
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
            community="example-rec", key="k", email="p@example.org", invite=True
        )

    assert result.invitation == "not_on_dev_list"
    assert result.invited is False
    assert kc.emails == []
    assert "example-rec/k" in caplog.text


async def test_in_dev_mode_an_address_on_the_list_is_invited(keycloak):
    kc = keycloak()

    result = await a_service(
        email_mode="dev", email_dev_recipients=" Someone@Example.org, p@example.org "
    ).ensure_participant(
        community="example-rec", key="k", email="P@example.org", invite=True
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
        community="example-rec", key="k", email="p@example.org", invite=True
    )

    assert not result.created
    assert result.invitation == "no_email"
    assert result.invited is False
    assert kc.send_attempts == 0


async def test_no_email_comes_before_the_dev_list(keycloak):
    bare = {"id": "u1", "username": "p@example.org", "enabled": True, "email": " "}
    kc = keycloak(users_by_username={"p@example.org": bare})

    result = await a_service(email_mode="dev").ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
    )

    assert result.invitation == "no_email"
    assert kc.send_attempts == 0


async def test_an_account_with_a_password_and_no_address_is_has_password(keycloak):
    """The existing order holds: a password means nothing to invite to."""
    bare = {"id": "u1", "username": "p@example.org", "enabled": True}
    kc = keycloak(users_by_username={"p@example.org": bare}, passwords_on={"u1"})

    result = await a_service().ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
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
        community="example-rec", key="k", email="p@example.org", invite=True
    )
    clock.now += 60
    second = await service.ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
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
        community="example-rec", key="k", email="p@example.org", invite=True
    )
    clock.now += 300
    again = await service.ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
    )

    assert again.invitation == "sent"
    assert len(kc.emails) == 2


async def test_a_route_send_puts_a_following_upsert_in_the_cooldown(keycloak, registry):
    """The same cooldown whichever call sent first."""
    kc = keycloak(**_existing())
    registry(
        documents=[
            {
                **EXAMPLE_REC,
                "members": {"k": {"user_id": "p@example.org", "name": "P", "status": "active"}},
            }
        ]
    )
    service = a_service(clock=Clock())

    await service.send_invitation(community="example-rec", key="k", intent="invitation")
    result = await service.ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
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
                **EXAMPLE_REC,
                "members": {"k": {"user_id": "p@example.org", "name": "P", "status": "active"}},
            }
        ]
    )
    service = a_service(clock=Clock())

    await service.send_invitation(community="example-rec", key="k", intent="password_reset")
    result = await service.ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
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
        community="example-rec", key="k", email="p@example.org", invite=True
    )
    kc.send_error = None
    retried = await service.ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
    )

    assert failed.invitation == "send_failed"
    assert failed.invited is False
    assert retried.invitation == "sent"
    assert len(kc.emails) == 1


async def test_a_new_account_whose_send_failed_is_still_created(keycloak):
    kc = keycloak(send_error=KeycloakError("Unexpected response 500", status_code=500))

    result = await a_service().ensure_participant(
        community="example-rec", key="k", email="new@example.org", invite=True
    )

    assert result.created
    assert result.invitation == "send_failed"
    assert "new@example.org" in kc.users_by_email


async def test_a_failed_route_send_lets_the_next_upsert_send(keycloak, registry):
    kc = keycloak(**_existing(), send_error=KeycloakError("500", status_code=500))
    registry(
        documents=[
            {
                **EXAMPLE_REC,
                "members": {"k": {"user_id": "p@example.org", "name": "P", "status": "active"}},
            }
        ]
    )
    service = a_service(clock=Clock())

    with pytest.raises(SendFailed):
        await service.send_invitation(community="example-rec", key="k", intent="invitation")
    kc.send_error = None
    result = await service.ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
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
                community="example-rec", key="k", email="p@example.org", invite=True
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
            community="example-rec", key="k", email="p@example.org", invite=True
        )
        assert result.invitation == "sent"

    assert len(kc.emails) == 2


# --- the lifecycle calls resolve through the registry --------------------


def _member(uuid="u1", username="ex-00001", *, enabled=True, email="one@example.org"):
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
        community="example-rec", key="20260912-a3f9c2", intent="invitation"
    )

    assert result.username == "a.person@example.org"
    assert result.invitation == "sent"
    assert [e["user_id"] for e in kc.emails] == ["uuid-legacy"]


async def test_an_account_without_a_password_is_invited_for_seven_days(keycloak, registry):
    kc = keycloak(users_by_username=_member())
    registry()

    result = await a_service().send_invitation(community="example-rec", key="ex-00001", intent="invitation")

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
        community="example-rec", key="ex-00001", intent="password_reset"
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
        await service.send_invitation(community="example-rec", key="ex-00001", intent="invitation")

    assert excinfo.value.code == "has_password"
    assert kc.send_attempts == 0

    result = await service.send_invitation(
        community="example-rec", key="ex-00001", intent="password_reset"
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
            community="example-rec", key="ex-00001", intent="password_reset"
        )

    assert excinfo.value.code == "no_password"
    assert kc.send_attempts == 0

    result = await service.send_invitation(
        community="example-rec", key="ex-00001", intent="invitation"
    )
    assert result.actions == ("UPDATE_PASSWORD", "VERIFY_EMAIL")
    assert len(kc.emails) == 1


async def test_a_mismatch_is_reported_as_such_even_within_the_cooldown(keycloak, registry):
    """The mismatch comes before the cooldown: the person is told to use the
    other button, not to wait for a clock."""
    kc = keycloak(users_by_username=_member(), passwords_on={"u1"})
    registry()
    service = a_service(clock=Clock())

    await service.send_invitation(community="example-rec", key="ex-00001", intent="password_reset")
    with pytest.raises(HasPassword):
        await service.send_invitation(community="example-rec", key="ex-00001", intent="invitation")

    assert len(kc.emails) == 1


async def test_a_disabled_account_is_account_disabled_whatever_the_intent(keycloak, registry):
    kc = keycloak(users_by_username=_member(enabled=False), passwords_on={"u1"})
    registry()

    for intent in ("invitation", "password_reset"):
        with pytest.raises(AccountDisabled):
            await a_service().send_invitation(
                community="example-rec", key="ex-00001", intent=intent
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
            community="example-rec", key="ex-00001", intent=intent
        )

    assert excinfo.value.code == "no_email"
    assert kc.send_attempts == 0


async def test_an_intent_mismatch_is_reported_before_a_missing_address(keycloak, registry):
    """The same order as the upsert: the password, then the address."""
    keycloak(users_by_username=_member(email=None), passwords_on={"u1"})
    registry()

    with pytest.raises(HasPassword):
        await a_service().send_invitation(community="example-rec", key="ex-00001", intent="invitation")


async def test_an_unknown_intent_from_a_direct_caller_sends_nothing(keycloak, registry):
    kc = keycloak(users_by_username=_member())
    registry()

    with pytest.raises(ValueError):
        await a_service().send_invitation(community="example-rec", key="ex-00001", intent="reset")

    assert kc.send_attempts == 0


async def test_no_password_is_generated_or_set_by_an_invitation(keycloak, registry):
    kc = keycloak(users_by_username=_member())
    registry()

    result = await a_service().send_invitation(community="example-rec", key="ex-00001", intent="invitation")

    assert kc.passwords == []
    assert not hasattr(result, "password")


async def test_an_invitation_to_a_disabled_account_is_refused_before_keycloak_is_asked(
    keycloak, registry
):
    kc = keycloak(users_by_username=_member(enabled=False))
    registry()

    with pytest.raises(AccountDisabled):
        await a_service().send_invitation(community="example-rec", key="ex-00001", intent="invitation")

    assert kc.emails == []


async def test_a_second_invitation_within_the_cooldown_is_refused(keycloak, registry):
    kc = keycloak(users_by_username=_member())
    registry()
    clock = Clock()
    service = a_service(clock=clock)

    await service.send_invitation(community="example-rec", key="ex-00001", intent="invitation")
    clock.now += 60
    with pytest.raises(InvitationCooldown) as excinfo:
        await service.send_invitation(community="example-rec", key="ex-00001", intent="invitation")

    assert excinfo.value.retry_after == 241
    assert len(kc.emails) == 1

    clock.now += 241
    await service.send_invitation(community="example-rec", key="ex-00001", intent="invitation")
    assert len(kc.emails) == 2


async def test_an_upsert_invitation_starts_the_cooldown_too(keycloak, registry):
    kc = keycloak()
    registry(
        documents=[
            {
                **EXAMPLE_REC,
                "members": {
                    "k": {"user_id": "p@example.org", "name": "P", "status": "active"}
                },
            }
        ]
    )
    service = a_service(clock=Clock())

    await service.ensure_participant(
        community="example-rec", key="k", email="p@example.org", invite=True
    )
    with pytest.raises(InvitationCooldown):
        await service.send_invitation(community="example-rec", key="k", intent="invitation")

    assert len(kc.emails) == 1


async def test_in_dev_mode_an_address_off_the_list_is_not_emailed_and_is_logged(
    keycloak, registry, caplog
):
    kc = keycloak(users_by_username=_member(email="someone@example.org"))
    registry()

    with caplog.at_level("WARNING"):
        result = await a_service(
            email_mode="dev", email_dev_recipients="allowed@example.org"
        ).send_invitation(community="example-rec", key="ex-00001", intent="invitation")

    assert result.invitation == "not_on_dev_list"
    assert kc.emails == []
    assert "example-rec/ex-00001" in caplog.text
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
        await service.send_invitation(community="example-rec", key="ex-00001", intent="invitation")
    assert excinfo.value.code == "send_failed"

    kc.send_error = None
    await service.send_invitation(community="example-rec", key="ex-00001", intent="invitation")
    assert len(kc.emails) == 1


async def test_disabling_revokes_without_deleting(keycloak, registry):
    kc = keycloak(
        users_by_username={"ex-00001": {"id": "u1", "username": "ex-00001", "enabled": True}}
    )
    registry()

    result = await a_service().disable(community="example-rec", key="ex-00001")

    assert result.changed
    assert kc.enabled_changes == [("u1", False)]
    assert "ex-00001" in kc.users_by_username  # nothing was deleted


async def test_disabling_twice_reports_no_change(keycloak, registry):
    """A revocation already in force must not read as one that just happened."""
    keycloak(
        users_by_username={"ex-00001": {"id": "u1", "username": "ex-00001", "enabled": False}}
    )
    registry()

    result = await a_service().disable(community="example-rec", key="ex-00001")

    assert not result.changed


@pytest.mark.parametrize("call", ["send_invitation", "disable"])
async def test_a_key_the_registry_does_not_hold_is_member_not_found(
    keycloak, registry, call
):
    keycloak()
    registry()

    with pytest.raises(MemberNotFound) as excinfo:
        await getattr(a_service(), call)(community="example-rec", key="nobody", **_intent(call))

    assert excinfo.value.code == "member_not_found"
    assert "nobody" in str(excinfo.value)


async def test_a_suspended_member_is_member_not_found(keycloak, registry):
    """The export carries every member; only `active` ones resolve."""
    keycloak(users_by_username=_member("u3", "ex-00003"))
    registry()

    with pytest.raises(MemberNotFound):
        await a_service().send_invitation(community="example-rec", key="ex-00003", intent="invitation")


@pytest.mark.parametrize("call", ["send_invitation", "disable"])
async def test_a_member_with_no_account_is_account_not_found_and_says_what_it_looked_for(
    keycloak, registry, call
):
    """The registry has the member, the realm has no account: a different
    thing to fix (provision it) from a member nobody has."""
    keycloak()
    registry()

    with pytest.raises(AccountNotFound) as excinfo:
        await getattr(a_service(), call)(community="example-rec", key="ex-00001", **_intent(call))

    assert not isinstance(excinfo.value, MemberNotFound)
    assert excinfo.value.code == "account_not_found"
    assert "ex-00001" in str(excinfo.value)


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
            await getattr(service, call)(community="nowhere", key="ex-00001", **_intent(call))

    assert excinfo.value.code == "community_not_found"
    assert "nowhere" in str(excinfo.value)
    assert kc.calls == []


async def test_a_registry_that_cannot_be_read_is_registry_unavailable(keycloak, registry):
    """Not a 404: an outage must not read as "nobody here"."""
    keycloak()
    registry(error=RegistryError("Could not export: 401"))

    with pytest.raises(RegistryUnavailable) as excinfo:
        await a_service().disable(community="example-rec", key="ex-00001")

    assert excinfo.value.code == "registry_unavailable"


async def test_no_registry_configured_refuses_with_the_variable_named(keycloak):
    keycloak()

    with pytest.raises(RegistryUnavailable) as excinfo:
        await a_service(registry_url=None).send_invitation(
            community="example-rec", key="ex-00001", intent="invitation"
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

    result = await a_service().reconcile("example-rec")

    assert result.members == 2
    assert result.created == 2
    provisioned = [c[1] for c in kc.calls if c[0] == "ensure_user"]
    assert provisioned == ["ex-00001", "a.person@example.org"]
    assert kc.enabled_changes == []


async def test_the_sweep_names_the_member_after_its_registry_row(keycloak, registry):
    """`user_id` and `key` disagree for anybody onboarding provisioned, and the
    row is what owns the username — deriving from the key would make a second
    account beside the one they already sign in with."""
    kc = keycloak()
    registry()

    await a_service().reconcile("example-rec")

    assert "20260912-a3f9c2" not in [c[1] for c in kc.calls if c[0] == "ensure_user"]


async def test_the_sweep_creates_no_credential(keycloak, registry):
    """A member the sweep creates is one nobody has been handed anything for.
    Inventing a password produces a secret that exists, grants access and was
    never given to anybody."""
    kc = keycloak()
    registry()

    await a_service().reconcile("example-rec")

    assert all(
        call[2]["temporary_password"] is None
        for call in kc.calls
        if call[0] == "ensure_user"
    )
    assert kc.passwords == []


async def test_a_healthy_sweep_finds_no_divergence(keycloak, registry):
    keycloak()
    registry()

    result = await a_service().reconcile("example-rec")

    assert result.divergences == ()


async def test_the_sweep_reports_a_membership_that_did_not_stick(keycloak, registry):
    """The assertion `a-grant-can-name-one-organization` owed. Everything it
    checks is something this same call claimed to have done, so a finding is a
    provisioning call that reported success and had not succeeded."""
    keycloak(organization_blackhole=True)
    registry()

    result = await a_service().reconcile("example-rec")

    assert len(result.divergences) == 2
    assert {d.kind for d in result.divergences} == {"not in the REC organization"}
    assert {d.key for d in result.divergences} == {"ex-00001", "20260912-a3f9c2"}


async def test_the_sweep_narrows_the_export_to_the_community_it_was_asked_about(
    keycloak, registry
):
    keycloak()
    calls = registry()

    await a_service().reconcile("example-rec")

    assert calls == [["example-rec"]]


async def test_more_than_one_document_for_one_community_is_refused(keycloak, registry):
    """The export was narrowed to one key, so anything else means the registry
    answered a question nobody asked."""
    keycloak()
    registry(documents=[EXAMPLE_REC, EXAMPLE_REC])

    with pytest.raises(ProvisioningError):
        await a_service().reconcile("example-rec")


# --- setting up a community that has no members yet -----------------------

#: A community the registry holds and nobody has been approved into: what a
#: clean community looks like before its first onboarding (ADR-0010). The
#: registry exports it with an empty `members` map.
EMPTY_REC = {
    "community": {"id": "example-rec", "name": "Example REC", "type": "rec"},
    "members": {},
}


class OrganizationKeycloak(FakeKeycloak):
    """A fake that remembers the organizations, org roles and org groups it
    was asked for, so a second call can be seen to create nothing."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        #: alias -> org id
        self.organizations: dict[str, str] = {}
        #: (org id, role name)
        self.org_roles: set[tuple[str, str]] = set()
        #: (org id, group name) -> group id
        self.org_groups: dict[tuple[str, str], str] = {}
        #: every create, in order: ("organization", alias), ("role", org, name), ...
        self.created: list[tuple] = []

    async def ensure_organization(self, *, alias, name, description, attributes):
        self.calls.append(("ensure_organization", alias))
        if alias in self.organizations:
            return self.organizations[alias], False
        self.organizations[alias] = f"org-{alias}"
        self.created.append(("organization", alias))
        return self.organizations[alias], True

    async def ensure_org_role(self, org_id, role_name):
        if (org_id, role_name) not in self.org_roles:
            self.org_roles.add((org_id, role_name))
            self.created.append(("role", org_id, role_name))

    async def ensure_org_group(self, org_id, name):
        if (org_id, name) in self.org_groups:
            return self.org_groups[(org_id, name)], False
        group_id = f"grp-{org_id}-{name}"
        self.org_groups[(org_id, name)] = group_id
        self.created.append(("group", org_id, name))
        return group_id, True


@pytest.fixture
def organization_keycloak(monkeypatch: pytest.MonkeyPatch) -> OrganizationKeycloak:
    fake = OrganizationKeycloak()
    monkeypatch.setattr(service_module, "KeycloakAdminClient", lambda *a, **k: fake)
    return fake


@pytest.mark.parametrize(
    "document",
    [
        EMPTY_REC,
        {"community": EMPTY_REC["community"]},
        {
            "community": EMPTY_REC["community"],
            "members": {"ex-00001": {"user_id": "ex-00001", "status": "pending"}},
        },
    ],
    ids=["empty-members", "no-members-key", "only-pending"],
)
async def test_a_community_with_no_members_gets_its_organization_roles_and_groups(
    organization_keycloak, registry, document
):
    """The organization, and the whole of `ROLE_HIERARCHY` as org roles and org
    groups, before anybody is approved — which is how a clean community gets
    them on a deployed realm.

    @verifies REQ-0002
    """
    kc = organization_keycloak
    registry(documents=[document])

    result = await a_service().reconcile("example-rec")

    assert result.community == "example-rec"
    assert (result.members, result.created, result.existing) == (0, 0, 0)
    assert result.divergences == ()
    assert kc.organizations == {"example-rec": "org-example-rec"}
    assert kc.org_roles == {
        ("org-example-rec", role) for role in ["admins", "managers", "editors", "viewers"]
    }
    assert set(kc.org_groups) == {
        ("org-example-rec", group) for group in ["admins", "managers", "editors", "viewers"]
    }
    # No account is created or touched for a community nobody belongs to.
    assert not [c for c in kc.calls if c[0] in ("ensure_user", "ensure_user_in_organization")]


async def test_a_second_setup_of_a_community_with_no_members_creates_nothing(
    organization_keycloak, registry
):
    """@verifies REQ-0002"""
    kc = organization_keycloak
    registry(documents=[EMPTY_REC])

    await a_service().reconcile("example-rec")
    first = list(kc.created)
    second = await a_service().reconcile("example-rec")

    assert len(first) == 1 + 4 + 4
    assert kc.created == first
    assert (second.members, second.created, second.existing) == (0, 0, 0)


async def test_setting_up_a_community_the_registry_does_not_have_creates_nothing(
    organization_keycloak, registry
):
    """`404 community_not_found`, and Keycloak is never opened.

    @verifies REQ-0002
    """
    kc = organization_keycloak
    registry(error=RegistryCommunityNotFound("http://registry has no community example-rec"))

    with pytest.raises(CommunityNotFound) as excinfo:
        await a_service().reconcile("example-rec")

    assert excinfo.value.code == "community_not_found"
    assert kc.calls == []
    assert kc.created == []


# --- correcting names and address (PATCH) ----------------------------------
#
# Onboarding plan "an operator corrects a member's declared data", R7: by
# username, never renamed, never created; `email_taken`; an address change
# resets `emailVerified` and sends the link to the new address only.


def _account(
    uuid="u1",
    username="ex-00001",
    *,
    email="old@example.org",
    first="One",
    last="Member",
    verified=True,
    enabled=True,
):
    return {
        "id": uuid,
        "username": username,
        "email": email,
        "firstName": first,
        "lastName": last,
        "emailVerified": verified,
        "enabled": enabled,
        "attributes": {"locale": ["it"]},
    }


def _writes(kc) -> list[tuple]:
    return [c for c in kc.calls if c[0] in ("update_user_profile", "put_user", "ensure_user")]


async def test_an_update_finds_the_account_by_its_registry_username(keycloak, registry):
    """The registry row says `a.person@example.org`; that is the account updated,
    whatever the key looks like.

    @verifies REQ-0007
    """
    kc = keycloak(
        users_by_username={
            "a.person@example.org": _account("uuid-legacy", "a.person@example.org")
        }
    )
    registry()

    result = await a_service().update_participant(
        community="example-rec", key="20260912-a3f9c2", first_name="Anna"
    )

    assert ("get_user_by_username", "a.person@example.org") in kc.calls
    assert result.keycloak_id == "uuid-legacy"
    assert result.username == "a.person@example.org"
    assert result.first_name == "Anna"
    assert result.changed == ("first_name",)


async def test_an_address_change_keeps_the_username_and_creates_no_account(
    keycloak, registry
):
    """@verifies REQ-0007"""
    account = _account()
    kc = keycloak(users_by_username={"ex-00001": account})
    registry()

    result = await a_service().update_participant(
        community="example-rec", key="ex-00001", email="new@example.org"
    )

    assert result.username == "ex-00001"
    assert account["username"] == "ex-00001"
    assert list(kc.users_by_username) == ["ex-00001"]
    assert not [c for c in kc.calls if c[0] == "ensure_user"]
    assert account["email"] == "new@example.org"
    assert account["attributes"] == {"locale": ["it"]}  # nothing else lost


async def test_an_address_change_resets_verified_and_emails_the_new_address_only(
    keycloak, registry
):
    """Keycloak sends to the account's address; the send happens after the
    write, so the only address it can reach is the new one.

    @verifies REQ-0007
    """
    account = _account(verified=True)
    kc = keycloak(users_by_username={"ex-00001": account})
    registry()

    result = await a_service().update_participant(
        community="example-rec", key="ex-00001", email="New@Example.org "
    )

    write = next(c for c in kc.calls if c[0] == "update_user_profile")
    assert write[4:] == ("New@Example.org", False)
    assert result.email_verified is False
    assert result.verification == "sent"
    assert result.changed == ("email",)
    # Keycloak's verification email, never an actions email: the theme renders
    # an actions email under the invitation's subject ("set your password")
    assert kc.emails == []
    assert kc.verifications == [
        {
            "user_id": "u1",
            "lifespan": 604800,
            "client_id": "oauth2_proxy",
            "redirect_uri": "http://webapp.celine.localhost/",
        }
    ]
    # Keycloak sends to the account's address: at the send it was the new one,
    # and nothing went to the old one
    assert kc.sent_to == ["New@Example.org"]
    assert "old@example.org" not in kc.sent_to
    assert kc.send_attempts == 1


async def test_the_same_address_in_another_case_is_not_a_change(keycloak, registry):
    """@verifies REQ-0007"""
    kc = keycloak(users_by_username={"ex-00001": _account(email="one@example.org")})
    registry()

    result = await a_service().update_participant(
        community="example-rec", key="ex-00001", email=" ONE@example.org"
    )

    assert result.changed == ()
    assert result.email_verified is True
    assert result.verification == "not_requested"
    assert _writes(kc) == []
    assert kc.emails == []


async def test_a_names_only_update_leaves_the_address_and_its_verification_alone(
    keycloak, registry
):
    """@verifies REQ-0007"""
    account = _account(verified=True)
    kc = keycloak(users_by_username={"ex-00001": account})
    registry()

    result = await a_service().update_participant(
        community="example-rec", key="ex-00001", first_name="Anna", last_name="Rossi"
    )

    write = next(c for c in kc.calls if c[0] == "update_user_profile")
    assert write[2:] == ("Anna", "Rossi", None, None)
    assert account["email"] == "old@example.org"
    assert account["emailVerified"] is True
    assert result.changed == ("first_name", "last_name")
    assert result.verification == "not_requested"
    assert kc.emails == []
    assert not [c for c in kc.calls if c[0] == "get_users_by_email"]


async def test_values_already_on_the_account_write_nothing(keycloak, registry):
    kc = keycloak(users_by_username={"ex-00001": _account()})
    registry()

    result = await a_service().update_participant(
        community="example-rec", key="ex-00001", first_name="One", last_name="Member"
    )

    assert result.changed == ()
    assert _writes(kc) == []


async def test_an_address_another_account_holds_is_email_taken_and_writes_nothing(
    keycloak, registry
):
    """@verifies REQ-0007"""
    other = _account("u2", "someone", email="Taken@Example.org")
    mine = _account()
    kc = keycloak(users_by_username={"ex-00001": mine, "someone": other})
    registry()

    with pytest.raises(EmailTaken) as excinfo:
        await a_service().update_participant(
            community="example-rec",
            key="ex-00001",
            first_name="Anna",
            email="taken@example.ORG",
        )

    assert excinfo.value.code == "email_taken"
    assert "taken@example" not in str(excinfo.value).lower()  # no address in the message
    assert _writes(kc) == []
    assert kc.emails == []
    assert mine["firstName"] == "One"


async def test_keycloaks_own_duplicate_refusal_is_email_taken(keycloak, registry):
    """A realm with `duplicateEmailsAllowed: false` answers 409 itself, e.g. on
    a race the read-before-write could not see."""
    kc = keycloak(
        users_by_username={"ex-00001": _account()},
        update_error=KeycloakConflictError("User exists with same email", status_code=409),
    )
    registry()

    with pytest.raises(EmailTaken):
        await a_service().update_participant(
            community="example-rec", key="ex-00001", email="new@example.org"
        )
    assert kc.emails == []


async def test_a_failed_verification_send_puts_the_account_back(keycloak, registry):
    account = _account(verified=True)
    kc = keycloak(
        users_by_username={"ex-00001": account},
        send_error=KeycloakError("Failed to send execute actions email", status_code=500),
    )
    registry()

    with pytest.raises(SendFailed):
        await a_service().update_participant(
            community="example-rec", key="ex-00001", first_name="Anna", email="new@example.org"
        )

    assert account["email"] == "old@example.org"
    assert account["emailVerified"] is True
    assert account["firstName"] == "One"
    assert ("put_user", "u1") in kc.calls

    # so a retry of the same call is a change again, and sends
    kc.send_error = None
    result = await a_service().update_participant(
        community="example-rec", key="ex-00001", first_name="Anna", email="new@example.org"
    )
    assert result.verification == "sent"
    assert len(kc.verifications) == 1


async def test_in_dev_mode_a_new_address_off_the_list_is_written_and_not_emailed(
    keycloak, registry
):
    account = _account()
    kc = keycloak(users_by_username={"ex-00001": account})
    registry()

    result = await a_service(email_mode="dev").update_participant(
        community="example-rec", key="ex-00001", email="new@example.org"
    )

    assert result.verification == "not_on_dev_list"
    assert account["email"] == "new@example.org"
    assert account["emailVerified"] is False
    assert kc.emails == [] and kc.verifications == []


async def test_the_verification_neither_waits_for_nor_starts_the_cooldown(
    keycloak, registry
):
    """The operator corrects the address because the invitation went astray;
    the link to the new address must not be held back by that invitation."""
    account = _account(email="wrong@example.org", verified=False)
    kc = keycloak(users_by_username={"ex-00001": account})
    registry()
    service = a_service(clock=Clock())

    await service.send_invitation(community="example-rec", key="ex-00001", intent="invitation")
    result = await service.update_participant(
        community="example-rec", key="ex-00001", email="right@example.org"
    )
    assert result.verification == "sent"

    with pytest.raises(InvitationCooldown):  # the invitation's own cooldown still stands
        await service.send_invitation(
            community="example-rec", key="ex-00001", intent="invitation"
        )
    assert [e["actions"] for e in kc.emails] == [["UPDATE_PASSWORD", "VERIFY_EMAIL"]]
    assert len(kc.verifications) == 1


async def test_an_update_of_a_disabled_account_is_refused_before_any_write(
    keycloak, registry
):
    kc = keycloak(users_by_username={"ex-00001": _account(enabled=False)})
    registry()

    with pytest.raises(AccountDisabled):
        await a_service().update_participant(
            community="example-rec", key="ex-00001", email="new@example.org"
        )
    assert _writes(kc) == []
    assert kc.emails == []


@pytest.mark.parametrize(
    "key,users,error,code",
    [
        ("nobody", {}, MemberNotFound, "member_not_found"),
        ("ex-00003", {"ex-00003": _account("u3", "ex-00003")}, MemberNotFound, "member_not_found"),
        ("ex-00001", {}, AccountNotFound, "account_not_found"),
    ],
    ids=["not-in-community", "not-active", "no-account"],
)
async def test_an_update_of_nobody_in_that_community_is_404_and_creates_nothing(
    keycloak, registry, key, users, error, code
):
    """@verifies REQ-0007"""
    kc = keycloak(users_by_username=users)
    registry()

    with pytest.raises(error) as excinfo:
        await a_service().update_participant(
            community="example-rec", key=key, email="new@example.org"
        )

    assert excinfo.value.code == code
    assert _writes(kc) == []
    assert kc.emails == []


async def test_an_update_in_a_community_the_registry_does_not_have_is_community_not_found(
    keycloak, registry
):
    kc = keycloak(users_by_username={"ex-00001": _account()})
    registry(error=RegistryCommunityNotFound("http://registry has no community nowhere"))

    with pytest.raises(CommunityNotFound):
        await a_service().update_participant(
            community="nowhere", key="ex-00001", first_name="Anna"
        )
    assert _writes(kc) == []


async def test_update_account_is_callable_by_username_without_the_registry(
    keycloak, registry
):
    """R13: the webapp's self-service will know the username from the member's
    own session; the work is the same function, with no registry read."""
    kc = keycloak(users_by_username={"ex-00001": _account()})
    calls = registry()

    result = await a_service().update_account("ex-00001", last_name="Rossi")

    assert calls == []
    assert result.changed == ("last_name",)
    assert kc.users_by_username["ex-00001"]["lastName"] == "Rossi"


async def test_an_update_logs_field_names_and_never_values(keycloak, registry, caplog):
    keycloak(users_by_username={"ex-00001": _account()})
    registry()

    with caplog.at_level("DEBUG"):
        await a_service().update_participant(
            community="example-rec",
            key="ex-00001",
            first_name="Anna",
            email="new@example.org",
        )

    text = caplog.text
    assert "first_name" in text and "email" in text
    assert "Anna" not in text
    assert "new@example.org" not in text


# --- the release: the login leaves the community, and is moved, not closed ---
#
# Requester, 2026-10-05: a REC admin releases a member; the account leaves the
# REC's organization and its groups, its sessions end, and it stays disabled
# until the next REC's upsert files it there and enables it again.


def _released_world(**kwargs):
    """ex-00001 as a participant of example-rec, also a member of an operator."""
    user = {"id": "u1", "username": "ex-00001", "enabled": True, "email": "one@example.org"}
    defaults = dict(
        users_by_username={"ex-00001": user},
        users_by_email={"one@example.org": user},
        organization_members={("org-example-rec", "u1"), ("org-example-dso", "u1")},
        org_group_members={
            ("org-example-rec", "grp-org-example-rec-viewers", "u1"),
            ("org-example-rec", "grp-org-example-rec-admins", "u1"),
        },
        org_types={"example-rec": "rec", "example-dso": "dso"},
    )
    defaults.update(kwargs)
    return defaults


async def test_a_release_disables_leaves_the_organization_and_its_groups_and_logs_out(
    keycloak, registry
):
    kc = keycloak(**_released_world())
    registry()

    result = await a_service().disable(community="example-rec", key="ex-00001")

    assert result.changed and result.disabled_now and result.org_left
    assert sorted(result.org_groups_left) == ["admins", "viewers"]
    assert result.sessions_logged_out
    assert kc.enabled_changes == [("u1", False)]
    assert ("org-example-rec", "u1") not in kc.org_members
    assert not any(m[0] == "org-example-rec" for m in kc.org_group_members)
    assert kc.logouts == ["u1"]
    # Nothing else is touched: the account and an operator's membership stay.
    assert "ex-00001" in kc.users_by_username
    assert ("org-example-dso", "u1") in kc.org_members


async def test_a_release_runs_in_the_order_a_retry_can_resume(keycloak, registry):
    """Disabled first, so nothing signs in while the rest runs; logged out last,
    so no session outlives the membership."""
    kc = keycloak(**_released_world())
    registry()

    await a_service().disable(community="example-rec", key="ex-00001")

    names = [c[0] for c in kc.calls]
    assert names.index("set_user_enabled") < names.index("remove_user_from_org_group")
    assert names.index("remove_user_from_org_group") < names.index("remove_user_from_organization")
    assert names.index("remove_user_from_organization") < names.index("logout_user")
    assert names[-1] == "logout_user"


async def test_releasing_twice_changes_nothing_and_still_ends_sessions(keycloak, registry):
    kc = keycloak(**_released_world())
    registry()
    service = a_service()

    await service.disable(community="example-rec", key="ex-00001")
    again = await service.disable(community="example-rec", key="ex-00001")

    assert not again.changed
    assert not again.disabled_now and not again.org_left and again.org_groups_left == ()
    assert kc.logouts == ["u1", "u1"]


async def test_a_release_of_an_account_disabled_by_an_older_revocation_still_moves_it(
    keycloak, registry
):
    """The old revocation disabled and kept the organization. Releasing it now
    finishes the job and says so: `changed`, but not `disabled_now`."""
    world = _released_world()
    world["users_by_username"]["ex-00001"]["enabled"] = False
    kc = keycloak(**world)
    registry()

    result = await a_service().disable(community="example-rec", key="ex-00001")

    assert result.changed and result.org_left and not result.disabled_now
    assert ("org-example-rec", "u1") not in kc.org_members


async def test_a_release_where_the_organization_does_not_exist_still_disables_and_logs_out(
    keycloak, registry
):
    kc = keycloak(**_released_world(org_types={}, organization_members=set(), org_group_members=set()))
    registry()

    result = await a_service().disable(community="example-rec", key="ex-00001")

    assert result.disabled_now and not result.org_left
    assert kc.logouts == ["u1"]


async def test_a_managed_membership_is_refused_and_nothing_is_removed(keycloak, registry):
    """Keycloak deletes a MANAGED member's account when it leaves the
    organization. The release destroys nothing, so it refuses."""
    kc = keycloak(**_released_world(managed={("org-example-rec", "u1")}))
    registry()

    with pytest.raises(ManagedMember) as excinfo:
        await a_service().disable(community="example-rec", key="ex-00001")

    assert excinfo.value.code == "managed_membership"
    assert ("org-example-rec", "u1") in kc.org_members
    assert not any(c[0] == "remove_user_from_organization" for c in kc.calls)


# --- the next REC's join -------------------------------------------------------


async def test_a_released_account_joining_another_rec_is_enabled_and_filed_there(keycloak):
    """The move's second half: found by its address, outside every REC, disabled;
    the upsert files it into the new REC and enables it again."""
    user = {"id": "u1", "username": "ex-00001", "enabled": False, "email": "one@example.org"}
    kc = keycloak(
        users_by_username={"ex-00001": user},
        users_by_email={"one@example.org": user},
        organization_members={("org-example-dso", "u1")},
        org_types={"example-dso": "dso"},
    )

    result = await a_service().ensure_participant(
        community="example-rec-b", key="ex-00009", email="one@example.org", invite=True
    )

    assert result.reenabled
    assert not result.created and result.username == "ex-00001"
    assert user["enabled"] is True
    assert ("org-example-rec-b", "u1") in kc.org_members
    # Enabled before the invitation is decided, so a person with no password yet
    # is invited rather than told `account_disabled`.
    assert result.invitation == "sent"


async def test_an_account_still_in_another_rec_is_refused_and_nothing_is_written(
    keycloak, caplog
):
    user = {"id": "u1", "username": "ex-00001", "enabled": True, "email": "one@example.org"}
    kc = keycloak(
        users_by_username={"ex-00001": user},
        users_by_email={"one@example.org": user},
        organization_members={("org-example-rec-a", "u1")},
        org_types={"example-rec-a": "rec"},
    )

    with caplog.at_level("WARNING"), pytest.raises(MemberOfAnotherCommunity) as excinfo:
        await a_service().ensure_participant(
            community="example-rec-b", key="ex-00009", email="one@example.org"
        )

    assert excinfo.value.code == "member_of_another_community"
    # The answer reaches the asking REC's operator: the other REC is not named
    # there, only in the platform's log.
    assert "example-rec-a" not in str(excinfo.value)
    assert "example-rec-a" in caplog.text
    assert [c[0] for c in kc.calls if c[0].startswith(("ensure_", "set_"))] == []
    assert kc.enabled_changes == []


async def test_an_operator_organization_is_not_another_rec(keycloak):
    """Only organizations typed `rec` count: a member who also works for the
    grid operator joins a REC as before."""
    user = {"id": "u1", "username": "ex-00001", "enabled": True, "email": "one@example.org"}
    kc = keycloak(
        users_by_username={"ex-00001": user},
        users_by_email={"one@example.org": user},
        organization_members={("org-example-dso", "u1")},
        org_types={"example-dso": "dso"},
    )

    result = await a_service().ensure_participant(
        community="example-rec", key="ex-00009", email="one@example.org"
    )

    assert not result.reenabled
    assert ("org-example-rec", "u1") in kc.org_members


async def test_rejoining_the_same_rec_is_not_another_community(keycloak):
    """A re-approval in the community the account is already in."""
    user = {"id": "u1", "username": "ex-00001", "enabled": True, "email": "one@example.org"}
    keycloak(
        users_by_username={"ex-00001": user},
        users_by_email={"one@example.org": user},
        organization_members={("org-example-rec", "u1")},
        org_types={"example-rec": "rec"},
    )

    result = await a_service().ensure_participant(
        community="example-rec", key="ex-00001", email="one@example.org"
    )

    assert result.username == "ex-00001"


async def test_a_member_already_inactive_in_the_registry_is_still_released(keycloak, registry):
    """An older revocation set the member inactive after disabling the login, and
    left the account in the organization. The release resolves it anyway: it only
    takes access away, and the next REC would otherwise refuse the person."""
    world = _released_world()
    world["users_by_username"]["ex-00003"] = world["users_by_username"].pop("ex-00001")
    world["users_by_username"]["ex-00003"]["username"] = "ex-00003"
    kc = keycloak(**world)
    registry()

    result = await a_service().disable(community="example-rec", key="ex-00003")

    assert result.org_left
    assert ("org-example-rec", "u1") not in kc.org_members


async def test_every_other_lifecycle_call_still_resolves_active_members_only(keycloak, registry):
    keycloak(users_by_username=_member("u3", "ex-00003"))
    registry()

    with pytest.raises(MemberNotFound):
        await a_service().update_participant(
            community="example-rec", key="ex-00003", first_name="Three"
        )
