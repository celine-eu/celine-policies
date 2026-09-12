"""`--check` reports divergence and writes nothing.

The deployment's own health probes cannot see any of this: organization
membership is not a liveness check, and the failure it produces is a person who
logs in and cannot see their own community. On 2026-09-11, 10 of 45
`/participants` members on demo3 were in their REC organization and nothing
anywhere said so.

So the point of this mode is not that it repairs anything — it repairs nothing —
but that a schedule can run it and a person hears about the next 10-of-45 without
looking. Two properties therefore matter more than the output's shape: **it must
write nothing**, or a scheduled check becomes a scheduled sync; and **it must not
under-report**, because an operator who chases one false finding stops reading the
next real one.

Nothing here talks to a Keycloak. What is covered is which questions `--check`
asks and what it concludes; see the store's `playbooks/testing.md`.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from celine.policies.cli.keycloak.commands import sync_users as sync_users_module
from celine.policies.cli.keycloak.commands.sync_users import (
    CommunityPlan,
    _async_check,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings

GREENLAND = CommunityPlan(
    community={"id": "greenland", "name": "Greenland", "description": ""},
    participants=[
        {"key": "gl-00001", "user_id": "gl-00001"},
        {"key": "20260912-a3f9c2", "user_id": "alice@example.com"},
    ],
    operators=[],
)

# Every call that writes. A check that touches one of these is a sync.
WRITES = (
    "ensure_organization",
    "ensure_organizations_enabled",
    "ensure_org_group",
    "ensure_org_role",
    "ensure_realm_claim_scopes",
    "ensure_realm_groups",
    "ensure_user",
    "ensure_user_in_org_group",
    "ensure_user_in_organization",
    "add_user_to_group_with_retry",
    "set_user_password",
    "create_user",
)


class FakeKeycloak:
    """Reads answer; every write raises."""

    def __init__(
        self,
        *,
        organizations: dict | None = None,
        users: dict | None = None,
        org_members: set | None = None,
        user_groups: dict | None = None,
    ):
        self.organizations = (
            {"greenland": {"id": "org-green"}} if organizations is None else organizations
        )
        self.users = (
            {"gl-00001": "uuid-1", "alice@example.com": "uuid-2"}
            if users is None
            else users
        )
        self.org_members = (
            {("org-green", "uuid-1"), ("org-green", "uuid-2")}
            if org_members is None
            else org_members
        )
        self.user_groups = {} if user_groups is None else user_groups

        self.authenticate = AsyncMock()
        for name in WRITES:
            setattr(self, name, self._forbidden(name))

    @staticmethod
    def _forbidden(name):
        async def refuse(*a, **k):
            raise AssertionError(f"--check must not call {name}")

        return refuse

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_organization_by_alias(self, alias: str):
        return self.organizations.get(alias)

    async def get_user_by_username(self, username: str):
        uuid = self.users.get(username)
        return {"id": uuid, "username": username} if uuid else None

    async def is_user_in_organization(self, org_id: str, user_id: str) -> bool:
        return (org_id, user_id) in self.org_members

    async def get_user_groups(self, user_id: str):
        return [{"path": p} for p in self.user_groups.get(user_id, [])]


@pytest.fixture
def kc_settings() -> KeycloakSettings:
    return KeycloakSettings(
        base_url="http://kc.internal", realm="celine", admin_client_secret="secret"
    )


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch):
    def install(**kwargs) -> FakeKeycloak:
        client = FakeKeycloak(**kwargs)
        monkeypatch.setattr(
            sync_users_module, "KeycloakAdminClient", lambda *a, **k: client
        )
        return client

    return install


async def check(kc_settings, **kwargs):
    return await _async_check(
        kc_settings=kc_settings,
        communities=kwargs.pop("communities", [GREENLAND]),
        **kwargs,
    )


class TestItWritesNothing:
    """The property that makes it safe to schedule."""

    @pytest.mark.asyncio
    async def test_a_fully_reconciled_realm_is_touched_by_nothing(
        self, fake, kc_settings
    ):
        fake()
        assert await check(kc_settings) == []

    @pytest.mark.asyncio
    async def test_a_diverged_realm_is_still_touched_by_nothing(
        self, fake, kc_settings
    ):
        """The tempting bug: report it, then fix it because you are already there."""
        fake(users={}, org_members=set())

        findings = await check(kc_settings)

        assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_a_missing_organization_is_not_created(self, fake, kc_settings):
        fake(organizations={})

        findings = await check(kc_settings)

        assert [f.kind for f in findings] == ["organization missing"]


class TestWhatItReports:
    @pytest.mark.asyncio
    async def test_a_member_with_no_account_is_a_finding(self, fake, kc_settings):
        fake(users={"gl-00001": "uuid-1"})

        findings = await check(kc_settings)

        assert [(f.key, f.kind) for f in findings] == [
            ("20260912-a3f9c2", "no Keycloak account")
        ]

    @pytest.mark.asyncio
    async def test_it_looks_the_account_up_by_the_user_id_not_the_key(
        self, fake, kc_settings
    ):
        """The same repair as Phase 1, on the reporting side.

        Looking up `20260912-a3f9c2` would report "no Keycloak account" for a
        participant who has one and logs in with it every day — a check that
        manufactures its own findings is worse than no check.
        """
        fake(users={"gl-00001": "uuid-1", "alice@example.com": "uuid-2"})

        assert await check(kc_settings) == []

    @pytest.mark.asyncio
    async def test_an_account_outside_the_rec_organization_is_a_finding(
        self, fake, kc_settings
    ):
        """The measured demo3 defect: 10 of 45, and nothing said so."""
        fake(org_members={("org-green", "uuid-1")})

        findings = await check(kc_settings)

        assert [(f.username, f.kind) for f in findings] == [
            ("alice@example.com", "not in the REC organization")
        ]

    @pytest.mark.asyncio
    async def test_the_organization_finding_says_what_it_costs(
        self, fake, kc_settings
    ):
        """"Not in an organization" does not tell an operator why they should care."""
        fake(org_members=set())

        findings = await check(kc_settings)

        assert "organization" in findings[0].detail
        assert "claim" in findings[0].detail

    @pytest.mark.asyncio
    async def test_an_account_outside_a_declared_admin_group_is_a_finding(
        self, fake, kc_settings
    ):
        fake(user_groups={"uuid-1": ["/participants"], "uuid-2": []})

        findings = await check(kc_settings, admin_group_paths=["/participants"])

        assert [(f.username, f.kind) for f in findings] == [
            ("alice@example.com", "not in /participants")
        ]

    @pytest.mark.asyncio
    async def test_no_declared_group_means_no_group_finding(self, fake, kc_settings):
        """A deployment declaring no `admin_permissions` sees nothing about groups."""
        fake(user_groups={})

        assert await check(kc_settings, admin_group_paths=[]) == []

    @pytest.mark.asyncio
    async def test_one_member_can_diverge_two_ways_at_once(self, fake, kc_settings):
        """Reporting only the first would hide half the repair.

        This is the shape the live demo3 run actually produced for an onboarded
        participant: outside the organization *and* outside `/participants`.
        """
        fake(org_members=set(), user_groups={})

        findings = await check(kc_settings, admin_group_paths=["/participants"])

        assert len(findings) == 4
        assert {f.kind for f in findings} == {
            "not in the REC organization",
            "not in /participants",
        }

    @pytest.mark.asyncio
    async def test_a_missing_organization_is_reported_once_not_per_member(
        self, fake, kc_settings
    ):
        """Otherwise one un-synced REC drowns every real per-member finding."""
        fake(organizations={})

        findings = await check(kc_settings)

        assert len(findings) == 1
        assert "2 member(s)" in findings[0].detail

    @pytest.mark.asyncio
    async def test_every_community_is_checked(self, fake, kc_settings):
        blueland = CommunityPlan(
            community={"id": "blueland", "name": "Blueland", "description": ""},
            participants=[{"key": "bl-1", "user_id": "bruno@example.com"}],
            operators=[],
        )
        fake(
            organizations={"greenland": {"id": "org-green"}},
            users={"gl-00001": "uuid-1", "alice@example.com": "uuid-2"},
        )

        findings = await check(kc_settings, communities=[GREENLAND, blueland])

        assert [f.community for f in findings] == ["blueland"]

    @pytest.mark.asyncio
    async def test_a_finding_names_the_community_the_key_and_the_username(
        self, fake, kc_settings
    ):
        """All three, because each answers a different question.

        The community says which REC drifted, the key is what to look up in the
        registry, and the username is what to look up in Keycloak.
        """
        fake(users={"gl-00001": "uuid-1"})

        rendered = str(await check(kc_settings) and (await check(kc_settings))[0])

        assert "greenland" in rendered
        assert "20260912-a3f9c2" in rendered
        assert "alice@example.com" in rendered
