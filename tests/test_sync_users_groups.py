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
from celine.policies.cli.keycloak.commands.sync_users import _async_sync_users
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

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_group_by_path(self, path: str):
        self.resolved_paths.append(path)
        return self.groups.get(path)

    async def ensure_user(self, username: str, **kwargs):
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


async def run(kc_settings, sync_settings, **kwargs):
    return await _async_sync_users(
        kc_settings=kc_settings,
        sync_settings=sync_settings,
        community_type="rec",
        participants=PARTICIPANTS,
        community=COMMUNITY,
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
                "/viewers": {"id": "gid-viewers"},
            }
        )
        settings = SyncUsersSettings(groups=["/viewers"], temp_password="pw")

        await run(kc_settings, settings, admin_group_paths=["/participants"])

        assert set(kc.group_adds) == {
            ("uuid-gl-0", "gid-participants"),
            ("uuid-gl-1", "gid-participants"),
            ("uuid-gl-0", "gid-viewers"),
            ("uuid-gl-1", "gid-viewers"),
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
