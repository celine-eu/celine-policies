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

import pytest

from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.provisioning import service as service_module
from celine.provisioning.config import ProvisioningSettings
from celine.provisioning.service import (
    MemberNotFound,
    ProvisioningError,
    ProvisioningService,
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
    ):
        self.users_by_email = users_by_email or {}
        self.users_by_username = users_by_username or {}
        self.org_members = organization_members or set()
        #: when set, `ensure_user_in_organization` reports success and the
        #: membership does not stick — the failure the sweep's assertion exists
        #: to catch.
        self.blackhole = organization_blackhole

        self.calls: list[tuple] = []
        self.passwords: list[tuple[str, str, bool]] = []
        self.enabled_changes: list[tuple[str, bool]] = []

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


def a_service(*, registry_url: str | None = "http://registry") -> ProvisioningService:
    return ProvisioningService(
        ProvisioningSettings(
            registry_url=registry_url,
            registry_client_id="svc-provisioning",
            registry_client_secret="secret",
        ),
        KeycloakSettings(
            base_url="http://kc.internal",
            realm="celine",
            admin_client_secret="secret",
        ),
    )


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


# --- the lifecycle calls resolve through the registry --------------------


async def test_a_password_reset_finds_the_member_by_its_registry_row(keycloak, registry):
    kc = keycloak(
        users_by_username={
            "a.person@example.org": {
                "id": "uuid-legacy",
                "username": "a.person@example.org",
                "enabled": True,
            }
        }
    )
    registry()

    result = await a_service().reset_password(
        community="greenland", key="20260912-a3f9c2"
    )

    assert result.username == "a.person@example.org"
    assert kc.passwords == [("uuid-legacy", result.password, True)]


async def test_the_credential_handed_back_is_temporary(keycloak, registry):
    """What travels back is a handover, never the participant's password."""
    keycloak(
        users_by_username={"gl-00001": {"id": "u1", "username": "gl-00001", "enabled": True}}
    )
    registry()

    result = await a_service().reset_password(community="greenland", key="gl-00001")

    assert len(result.password) >= 12


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


async def test_a_key_the_registry_does_not_hold_is_not_found(keycloak, registry):
    keycloak()
    registry()

    with pytest.raises(MemberNotFound) as excinfo:
        await a_service().reset_password(community="greenland", key="nobody")

    assert "nobody" in str(excinfo.value)


async def test_a_member_with_no_account_is_not_found_and_says_what_it_looked_for(
    keycloak, registry
):
    keycloak()
    registry()

    with pytest.raises(MemberNotFound) as excinfo:
        await a_service().disable(community="greenland", key="gl-00001")

    assert "gl-00001" in str(excinfo.value)


async def test_no_registry_configured_refuses_with_the_variable_named(keycloak):
    keycloak()

    with pytest.raises(ProvisioningError) as excinfo:
        await a_service(registry_url=None).reset_password(
            community="greenland", key="gl-00001"
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
