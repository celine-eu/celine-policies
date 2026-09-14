"""`sync-users` files its participants in the group the grant administers.

A service account granted over `/participants` can only see what is in
`/participants`. `sync_users` created its users with the organization membership
and whatever `--group` paths were passed, so nothing it made landed there:
onboarding then attempted a create, got `409 User exists with same username`,
scanned the group and did not find the account — an enablement step failing on a
participant that plainly exists (celine-policies#3).

The paths come from the same `admin_permissions` block `sync` grants from, so the
two commands cannot name different groups. Every participant is added whether the
account was just created or already existed, which is what makes a re-run the
backfill for the accounts created before this existed.

Nothing here talks to a Keycloak — the client is a fake, so what is covered is
which calls `sync-users` decides to make, not that Keycloak accepts them. See the
store's `playbooks/testing.md`.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from celine.policies.cli.keycloak.client import KeycloakError
from celine.policies.cli.keycloak.commands import sync_users as sync_users_module
from celine.policies.cli.keycloak.commands.sync_users import (
    CommunityPlan,
    _async_sync_users,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings, SyncUsersSettings

COMMUNITY = {"id": "greenland", "name": "Greenland", "description": "", "type": "rec"}
PARTICIPANTS = [{"key": "gl-0"}, {"key": "gl-1"}]


class FakeKeycloak:
    """Every call `_async_sync_users` makes, recorded rather than performed."""

    def __init__(self, *, existing_users: set[str] | None = None, groups: dict | None = None):
        self.existing_users = existing_users or set()
        self.groups = {} if groups is None else groups

        # what the assertions read
        self.group_adds: list[tuple[str, str]] = []
        self.created_users: list[str] = []
        self.resolved_paths: list[str] = []

        self.authenticate = AsyncMock()
        self.ensure_organizations_enabled = AsyncMock(return_value=False)
        self.ensure_realm_claim_scopes = AsyncMock(return_value=False)
        self.get_client_by_client_id = AsyncMock(return_value=None)
        self.ensure_audience_mapper = AsyncMock(return_value=False)
        self.ensure_organization = AsyncMock(return_value=("org-1", False))
        self.get_organization_by_alias = AsyncMock(return_value={"id": "org-1"})
        self.ensure_org_role = AsyncMock()
        self.ensure_org_group = AsyncMock(return_value=("orggrp-1", False))
        self.ensure_realm_groups = AsyncMock(return_value=False)
        self.ensure_user_in_organization = AsyncMock(return_value=False)
        self.ensure_user_in_org_group = AsyncMock()
        self.set_user_password = AsyncMock()
        self.get_user_by_username = AsyncMock(return_value=None)
        self.execute_actions_email = AsyncMock()
        self.ensure_user_kwargs: dict[str, dict] = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_group_by_path(self, path: str):
        self.resolved_paths.append(path)
        return self.groups.get(path)

    async def ensure_user(self, username: str, **kwargs):
        self.ensure_user_kwargs[username] = kwargs
        if username in self.existing_users:
            return f"uuid-{username}", False
        self.created_users.append(username)
        return f"uuid-{username}", True

    async def add_user_to_group_with_retry(self, user_uuid: str, group_id: str):
        self.group_adds.append((user_uuid, group_id))


@pytest.fixture
def kc_settings() -> KeycloakSettings:
    return KeycloakSettings(
        base_url="http://kc.internal", realm="celine", admin_client_secret="secret"
    )


@pytest.fixture
def sync_settings() -> SyncUsersSettings:
    return SyncUsersSettings(groups=[], temp_password="pw", dry_run=False)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch):
    """Install a fake client and hand it back for inspection."""

    def install(**kwargs) -> FakeKeycloak:
        client = FakeKeycloak(**kwargs)
        monkeypatch.setattr(
            sync_users_module, "KeycloakAdminClient", lambda *a, **k: client
        )
        return client

    return install


async def run(kc_settings, sync_settings, *, participants=None, communities=None, **kwargs):
    if communities is None:
        communities = [
            CommunityPlan(
                community=COMMUNITY,
                participants=PARTICIPANTS if participants is None else participants,
                operators=[],
            )
        ]
    return await _async_sync_users(
        kc_settings=kc_settings,
        sync_settings=sync_settings,
        communities=communities,
        **kwargs,
    )


class TestParticipantsLandInTheAdministeredGroup:
    @pytest.mark.asyncio
    async def test_a_new_participant_is_added_to_the_declared_group(
        self, fake, kc_settings, sync_settings
    ):
        kc = fake(groups={"/participants": {"id": "gid-participants"}})

        created, _, errors = await run(
            kc_settings, sync_settings, admin_group_paths=["/participants"]
        )

        assert errors == []
        assert created == ["gl-0", "gl-1"]
        assert kc.group_adds == [
            ("uuid-gl-0", "gid-participants"),
            ("uuid-gl-1", "gid-participants"),
        ]

    @pytest.mark.asyncio
    async def test_an_existing_participant_is_added_too_which_is_the_backfill(
        self, fake, kc_settings, sync_settings
    ):
        """The accounts already made by earlier runs, filed in no group."""
        kc = fake(
            existing_users={"gl-0", "gl-1"},
            groups={"/participants": {"id": "gid-participants"}},
        )

        created, skipped, errors = await run(
            kc_settings, sync_settings, admin_group_paths=["/participants"]
        )

        assert errors == []
        assert created == []
        assert skipped == ["gl-0", "gl-1"]
        assert kc.group_adds == [
            ("uuid-gl-0", "gid-participants"),
            ("uuid-gl-1", "gid-participants"),
        ]

    @pytest.mark.asyncio
    async def test_several_declared_groups_are_all_filled(
        self, fake, kc_settings, sync_settings
    ):
        kc = fake(
            groups={
                "/participants": {"id": "gid-participants"},
                "/members": {"id": "gid-members"},
            }
        )

        await run(
            kc_settings,
            sync_settings,
            admin_group_paths=["/participants", "/members"],
        )

        assert set(kc.group_adds) == {
            ("uuid-gl-0", "gid-participants"),
            ("uuid-gl-1", "gid-participants"),
            ("uuid-gl-0", "gid-members"),
            ("uuid-gl-1", "gid-members"),
        }

    @pytest.mark.asyncio
    async def test_explicit_group_flags_still_work_alongside(
        self, fake, kc_settings
    ):
        """`--group` is not replaced by the declaration, it is joined by it."""
        kc = fake(
            groups={
                "/participants": {"id": "gid-participants"},
                "/pilot": {"id": "gid-pilot"},
            }
        )
        settings = SyncUsersSettings(groups=["/pilot"], temp_password="pw")

        await run(kc_settings, settings, admin_group_paths=["/participants"])

        assert set(kc.group_adds) == {
            ("uuid-gl-0", "gid-participants"),
            ("uuid-gl-1", "gid-participants"),
            ("uuid-gl-0", "gid-pilot"),
            ("uuid-gl-1", "gid-pilot"),
        }


class TestInertWithoutADeclaration:
    """Everyone not using admin permissions sees `sync-users` behave as before."""

    @pytest.mark.asyncio
    async def test_no_declared_group_resolves_no_group_and_adds_nobody(
        self, fake, kc_settings, sync_settings
    ):
        kc = fake()

        created, _, errors = await run(
            kc_settings, sync_settings, admin_group_paths=[]
        )

        assert errors == []
        assert created == ["gl-0", "gl-1"]
        assert kc.resolved_paths == []
        assert kc.group_adds == []

    @pytest.mark.asyncio
    async def test_the_argument_is_optional(self, fake, kc_settings, sync_settings):
        kc = fake()

        await run(kc_settings, sync_settings)

        assert kc.group_adds == []


class TestAMissingGroupFailsBeforeAnyUserIsTouched:
    """`sync` owns realm structure and creates the group when it grants.

    A missing one means the realm was not synced from the declaration this
    command just read, and creating it here would paper over that. Resolved up
    front, like `--group`, so the run does not stop half way through leaving some
    participants filed and some not.
    """

    @pytest.mark.asyncio
    async def test_it_raises(self, fake, kc_settings, sync_settings):
        fake(groups={})

        with pytest.raises(KeycloakError, match="/participants"):
            await run(
                kc_settings, sync_settings, admin_group_paths=["/participants"]
            )

    @pytest.mark.asyncio
    async def test_no_user_is_created_first(self, fake, kc_settings, sync_settings):
        kc = fake(groups={})

        with pytest.raises(KeycloakError):
            await run(
                kc_settings, sync_settings, admin_group_paths=["/participants"]
            )

        assert kc.created_users == []

    @pytest.mark.asyncio
    async def test_the_message_names_the_way_out(
        self, fake, kc_settings, sync_settings
    ):
        """An operator reading it must not have to guess which command to run."""
        fake(groups={})

        with pytest.raises(KeycloakError) as excinfo:
            await run(
                kc_settings, sync_settings, admin_group_paths=["/participants"]
            )

        assert "keycloak sync" in str(excinfo.value)
        assert "--no-admin-groups" in str(excinfo.value)


class TestTheAccountIsNamedAfterTheRegistryRow:
    """`user_id` names the account, and the key is only the fallback.

    The command used to derive the username from the member key and ignore the
    `user_id` it had already loaded. That is invisible against a
    hand-maintained file — the same hand wrote both columns — and it duplicates
    every onboarded participant against the live registry, because
    `../onboarding` writes `key = submission.ref` and `user_id` = the username
    Keycloak returned.

    Nothing here talks to a Keycloak, so what is covered is which username
    `sync-users` decides to provision. That a re-run against a real realm is
    then a no-op rather than a second account is checked by hand; see the
    store's `playbooks/verifying-a-realm-against-a-real-keycloak.md`.
    """

    ONBOARDED = [{"key": "20260912-a3f9c2", "user_id": "alice@example.com"}]

    @pytest.mark.asyncio
    async def test_the_user_id_is_provisioned_not_the_key(
        self, fake, kc_settings, sync_settings
    ):
        kc = fake()

        created, _, errors = await run(
            kc_settings, sync_settings, participants=self.ONBOARDED
        )

        assert errors == []
        assert kc.created_users == ["alice@example.com"]
        assert created == ["alice@example.com"]

    @pytest.mark.asyncio
    async def test_the_account_onboarding_made_is_adopted_not_duplicated(
        self, fake, kc_settings, sync_settings
    ):
        """The defect, stated as the behaviour that closes it.

        With the account already present under the name onboarding gave it, the
        run must skip rather than create. Deriving from the key would have found
        nothing and created `20260912-a3f9c2` beside it.
        """
        kc = fake(existing_users={"alice@example.com"})

        created, skipped, errors = await run(
            kc_settings, sync_settings, participants=self.ONBOARDED
        )

        assert errors == []
        assert kc.created_users == []
        assert created == []
        assert skipped == ["alice@example.com"]

    @pytest.mark.asyncio
    async def test_a_row_with_no_user_id_still_uses_the_key(
        self, fake, kc_settings, sync_settings
    ):
        """The seed case keeps working, which is why the fallback survives."""
        kc = fake()

        await run(
            kc_settings,
            sync_settings,
            participants=[{"key": "GL-00001", "user_id": None}],
        )

        assert kc.created_users == ["gl-00001"]

    @pytest.mark.asyncio
    async def test_the_dry_run_looks_up_the_same_name_it_would_create(
        self, fake, kc_settings
    ):
        """The two branches used to compute the username separately.

        A dry run that probes one name and a live run that creates another is
        the worst of both: the plan says "exists" and the run makes a duplicate.
        """
        kc = fake()
        settings = SyncUsersSettings(temp_password="pw", dry_run=True)

        await run(kc_settings, settings, participants=self.ONBOARDED)

        kc.get_user_by_username.assert_awaited_once_with("alice@example.com")

    @pytest.mark.asyncio
    async def test_mock_does_not_double_an_address_that_is_already_one(
        self, fake, kc_settings, sync_settings
    ):
        """`--mock` appends a domain, and the username is now often an email.

        `f"{username}@celine.localhost"` would produce
        `alice@example.com@celine.localhost` — an address Keycloak accepts and
        nobody can receive mail at.
        """
        kc = fake()
        captured: dict = {}

        async def ensure_user(username: str, **kwargs):
            captured[username] = kwargs
            kc.created_users.append(username)
            return f"uuid-{username}", True

        kc.ensure_user = ensure_user

        await run(kc_settings, sync_settings, participants=self.ONBOARDED, mock=True)

        assert captured["alice@example.com"]["email"] == "alice@example.com"

    @pytest.mark.asyncio
    async def test_mock_still_synthesises_one_for_a_seeded_key(
        self, fake, kc_settings, sync_settings
    ):
        kc = fake()
        captured: dict = {}

        async def ensure_user(username: str, **kwargs):
            captured[username] = kwargs
            kc.created_users.append(username)
            return f"uuid-{username}", True

        kc.ensure_user = ensure_user

        await run(
            kc_settings,
            sync_settings,
            participants=[{"key": "gl-00001", "user_id": "gl-00001"}],
            mock=True,
        )

        assert captured["gl-00001"]["email"] == "gl-00001@celine.localhost"


class TestTheRealmScaffoldRunsOncePerRunNotOncePerCommunity:
    """Claim scopes, realm groups and the proxy audience mapper are realm-wide.

    There was one community per run before, so realm-level and community-level
    work were interleaved and the distinction did not exist. Reconciling every
    REC in one pass is what makes it matter: running the realm half per
    community is a multiple of the same idempotent writes, and it grows with
    the number of communities rather than staying flat.
    """

    COMMUNITIES = [
        CommunityPlan(
            community={"id": "greenland", "name": "Greenland", "description": ""},
            participants=[{"key": "gl-1", "user_id": "gl-1"}],
            operators=[],
        ),
        CommunityPlan(
            community={"id": "blueland", "name": "Blueland", "description": ""},
            participants=[{"key": "bl-1", "user_id": "bruno@example.com"}],
            operators=[],
        ),
    ]

    @pytest.mark.asyncio
    async def test_the_realm_level_calls_happen_exactly_once(
        self, fake, kc_settings, sync_settings
    ):
        kc = fake()

        await run(kc_settings, sync_settings, communities=self.COMMUNITIES)

        assert kc.ensure_organizations_enabled.await_count == 1
        assert kc.ensure_realm_claim_scopes.await_count == 1
        assert kc.ensure_realm_groups.await_count == 1

    @pytest.mark.asyncio
    async def test_the_organization_is_ensured_once_per_community(
        self, fake, kc_settings, sync_settings
    ):
        kc = fake()

        await run(kc_settings, sync_settings, communities=self.COMMUNITIES)

        aliases = [c.kwargs["alias"] for c in kc.ensure_organization.await_args_list]
        assert aliases == ["greenland", "blueland"]

    @pytest.mark.asyncio
    async def test_every_community_s_members_are_provisioned(
        self, fake, kc_settings, sync_settings
    ):
        kc = fake()

        created, _, errors = await run(
            kc_settings, sync_settings, communities=self.COMMUNITIES
        )

        assert errors == []
        assert kc.created_users == ["gl-1", "bruno@example.com"]
        assert created == ["gl-1", "bruno@example.com"]

    @pytest.mark.asyncio
    async def test_the_declared_group_is_resolved_once_and_filled_for_everybody(
        self, fake, kc_settings, sync_settings
    ):
        """One resolution, every community's members in it.

        The group is realm-level and flat (ADR-0005), so it is resolved with the
        rest of the realm scaffold — and a participant of the second community
        must land in it just the same, or that community is the one onboarding
        cannot find.
        """
        kc = fake(groups={"/participants": {"id": "gid-participants"}})

        await run(
            kc_settings,
            sync_settings,
            communities=self.COMMUNITIES,
            admin_group_paths=["/participants"],
        )

        assert kc.resolved_paths == ["/participants"]
        assert kc.group_adds == [
            ("uuid-gl-1", "gid-participants"),
            ("uuid-bruno@example.com", "gid-participants"),
        ]

    @pytest.mark.asyncio
    async def test_a_missing_group_fails_before_the_first_community(
        self, fake, kc_settings, sync_settings
    ):
        """Resolution is up front, so no community is half provisioned."""
        kc = fake(groups={})

        with pytest.raises(KeycloakError, match="/participants"):
            await run(
                kc_settings,
                sync_settings,
                communities=self.COMMUNITIES,
                admin_group_paths=["/participants"],
            )

        assert kc.created_users == []


class TestAdoptingAnOnboardedAccountDoesNotModifyIt:
    """With registration open, most members already have an account.

    `../onboarding` provisions the Keycloak user *first* and the registry member
    second, so from the next deploy onwards `sync-users` is mostly an adopter
    rather than a creator: the account exists, it has the participant's real
    email, and the participant has already signed in with it.

    What it must therefore never do is write to one. Overwriting an email or
    resetting a password on a live account is not a sync — it is an outage for
    one person, and it would be caused by the command that was supposed to be
    reconciling them.
    """

    ONBOARDED = [{"key": "20260912-a3f9c2", "user_id": "alice@example.com"}]

    @pytest.mark.asyncio
    async def test_no_password_is_set_on_an_account_that_already_exists(
        self, fake, kc_settings, sync_settings
    ):
        kc = fake(existing_users={"alice@example.com"})

        await run(kc_settings, sync_settings, participants=self.ONBOARDED)

        kc.set_user_password.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_reset_password_is_opt_in_and_still_available(
        self, fake, kc_settings, sync_settings
    ):
        """The seed-demo case has to keep working; it is just not the default."""
        kc = fake(existing_users={"alice@example.com"})

        await run(
            kc_settings,
            sync_settings,
            participants=self.ONBOARDED,
            reset_password=True,
        )

        kc.set_user_password.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_mock_does_not_overwrite_a_real_email_on_an_existing_account(
        self, fake, kc_settings, sync_settings
    ):
        """`--mock` fills fields on accounts it creates, and must stop there.

        `ensure_user` returns early for a user that exists, so the email,
        firstName and lastName passed to it are only ever used on a create.
        Pinned because `--mock` is exactly what a developer reaches for while
        testing this against a realm holding real onboarded accounts.
        """
        kc = fake(existing_users={"alice@example.com"})
        captured: list = []

        async def ensure_user(username: str, **kwargs):
            captured.append((username, kwargs))
            return f"uuid-{username}", False

        kc.ensure_user = ensure_user

        await run(kc_settings, sync_settings, participants=self.ONBOARDED, mock=True)

        assert captured[0][0] == "alice@example.com"
        assert kc.created_users == []
        kc.set_user_password.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_the_organization_and_the_group_are_still_ensured(
        self, fake, kc_settings, sync_settings
    ):
        """Adopting is not doing nothing — it is the half onboarding cannot do.

        Organization membership is the whole reason this run matters for an
        already-provisioned participant: `../onboarding` sets the group and not
        the organization, so an onboarded member has no `organization` claim
        until something reconciles them. This is that something.
        """
        kc = fake(
            existing_users={"alice@example.com"},
            groups={"/participants": {"id": "gid-participants"}},
        )

        await run(
            kc_settings,
            sync_settings,
            participants=self.ONBOARDED,
            admin_group_paths=["/participants"],
        )

        kc.ensure_user_in_organization.assert_awaited_once_with(
            "org-1", "uuid-alice@example.com"
        )
        assert kc.group_adds == [("uuid-alice@example.com", "gid-participants")]


class TestInviteOnlyWhatThisRunCreated:
    """`--invite`: the plan's guard for `sync-users`
    (`a-participant-is-invited-and-sets-their-own-password`, Phase 4).

    A reconcile that invited every member without a password on every run would
    spam anyone who has not yet acted on their email, so only an account created
    in this run is invited — and it is created with no password at all.
    """

    PARTICIPANTS = [{"key": "gl-0", "user_id": "new@example.org"}, {"key": "gl-1", "user_id": "old@example.org"}]

    @staticmethod
    def invitations(mode="deliver", recipients=""):
        from celine.policies.cli.keycloak.commands.sync_users import InvitationSettings
        from celine.provisioning.invitation import EmailPolicy, parse_recipients

        return InvitationSettings(
            policy=EmailPolicy(mode=mode, dev_recipients=parse_recipients(recipients)),
            lifespan=604800,
            client_id="oauth2_proxy",
            redirect_uri="http://webapp.celine.localhost/",
        )

    @pytest.mark.asyncio
    async def test_only_the_account_created_in_this_run_is_invited_and_it_has_no_password(
        self, fake, kc_settings
    ):
        kc = fake(existing_users={"old@example.org"})
        settings = SyncUsersSettings(groups=[], dry_run=False)

        created, skipped, errors = await run(
            kc_settings,
            settings,
            participants=self.PARTICIPANTS,
            mock=True,
            invitations=self.invitations(),
        )

        assert errors == []
        assert created == ["new@example.org"]
        kc.execute_actions_email.assert_awaited_once_with(
            "uuid-new@example.org",
            ["UPDATE_PASSWORD", "VERIFY_EMAIL"],
            lifespan=604800,
            client_id="oauth2_proxy",
            redirect_uri="http://webapp.celine.localhost/",
        )
        assert kc.ensure_user_kwargs["new@example.org"]["temporary_password"] is None
        kc.set_user_password.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_in_dev_mode_an_address_off_the_list_is_not_emailed(
        self, fake, kc_settings, caplog
    ):
        kc = fake()
        settings = SyncUsersSettings(groups=[], dry_run=False)

        with caplog.at_level("WARNING"):
            await run(
                kc_settings,
                settings,
                participants=self.PARTICIPANTS,
                mock=True,
                invitations=self.invitations(mode="dev", recipients="old@example.org"),
            )

        assert [c.args[0] for c in kc.execute_actions_email.await_args_list] == [
            "uuid-old@example.org"
        ]
        assert "greenland/gl-0" in caplog.text

    @pytest.mark.asyncio
    async def test_an_account_with_no_address_is_not_invited(self, fake, kc_settings):
        """The registry holds no email; outside `--mock` there is nobody to write to."""
        kc = fake()
        settings = SyncUsersSettings(groups=[], dry_run=False)

        created, _, errors = await run(
            kc_settings,
            settings,
            participants=self.PARTICIPANTS,
            invitations=self.invitations(),
        )

        assert errors == []
        assert len(created) == 2
        kc.execute_actions_email.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_without_invite_nothing_is_emailed(self, fake, kc_settings, sync_settings):
        kc = fake()

        await run(kc_settings, sync_settings, participants=self.PARTICIPANTS, mock=True)

        kc.execute_actions_email.assert_not_awaited()
