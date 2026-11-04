"""Declared platform-admin accounts: `bootstrap` creates them, once (REQ-0022).

A `platform_admin.users` entry is a username, as before (granted when the account exists,
reported while it does not), or an account: `{username, email, first_name, last_name}`.
A declared account that does not exist is created with a temporary password the user must
change at first sign-in, then granted `platform-admin`; the admin second factor follows from
the role (REQ-0015). An existing account is never rewritten: not its password, not its email,
and a disabled one is not enabled again. Each of those is reported.

The temporary password is never in the declaration: `CELINE_KEYCLOAK_PLATFORM_ADMIN_PASSWORD_<USERNAME>`
for one account, or `CELINE_KEYCLOAK_PLATFORM_ADMIN_PASSWORD_TEMPLATE` with `{username}` for all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from celine.policies.cli.keycloak.platform import (
    PlatformDeclarationError,
    load_platform,
)
from celine.policies.cli.keycloak.settings import platform_admin_password
from test_platform_declaration import FakeRealm, a_declaration, converge_platform, write

ALICE = {"username": "alice", "email": "alice@example.org", "first_name": "Alice", "last_name": "Doe"}


def declared(tmp_path: Path, users: str):
    return a_declaration(tmp_path, extra=f"platform_admin:\n  role: platform-admin\n  users: {users}\n")


async def converge(kc, declaration, *, dry_run=False, passwords=None):
    passwords = passwords or {}
    return await converge_platform(
        kc, declaration, brute_force_protected=False, dry_run=dry_run,
        admin_password=passwords.get,
    )


def realm(**kwargs) -> FakeRealm:
    kc = FakeRealm({"bruteForceProtected": False}, **kwargs)
    kc.roles.add("platform-admin")
    return kc


ALICE_YAML = "[{username: alice, email: alice@example.org, first_name: Alice, last_name: Doe}]"


# ---------------------------------------------------------------------------
# The declaration
# ---------------------------------------------------------------------------


class TestTheDeclaration:
    def test_a_username_is_still_a_username(self, tmp_path):
        d = declared(tmp_path, "[bob]")
        assert d.platform_admins == ["bob"]
        assert d.platform_admin_accounts == {}

    def test_an_account_names_its_user(self, tmp_path):
        d = declared(tmp_path, f"[bob, {ALICE_YAML[1:-1]}]")
        assert d.platform_admins == ["bob", "alice"]
        assert d.platform_admin_accounts == {"alice": {k: v for k, v in ALICE.items() if k != "username"}}

    @pytest.mark.parametrize("missing", ["email", "first_name", "last_name"])
    def test_an_account_without_a_profile_field_is_refused(self, tmp_path, missing):
        fields = ", ".join(f"{k}: {v}" for k, v in ALICE.items() if k != missing)
        with pytest.raises(PlatformDeclarationError, match=missing):
            declared(tmp_path, f"[{{{fields}}}]")

    def test_a_password_in_the_declaration_is_refused(self, tmp_path):
        with pytest.raises(PlatformDeclarationError, match="password"):
            declared(tmp_path, "[{username: alice, email: a@x.org, first_name: A, last_name: D, password: x}]")

    def test_a_user_declared_twice_is_refused(self, tmp_path):
        with pytest.raises(PlatformDeclarationError, match="distinct"):
            declared(tmp_path, f"[alice, {ALICE_YAML[1:-1]}]")

    def test_an_overlay_may_declare_accounts(self, tmp_path):
        base = write(tmp_path, "platform.yaml", "platform_admin:\n  role: platform-admin\n  users: []\n")
        overlay = write(tmp_path, "admins.yaml", f"platform_admin:\n  users: {ALICE_YAML}\n")
        d = load_platform(base, overlays=[overlay])
        assert d.platform_admins == ["alice"]
        assert "alice" in d.platform_admin_accounts


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------


class TestAMissingAccount:
    @pytest.mark.asyncio
    async def test_is_created_with_a_temporary_password_and_granted(self, tmp_path):
        """@verifies REQ-0022"""
        kc = realm()
        result = await converge(kc, declared(tmp_path, ALICE_YAML), passwords={"alice": "tmp-1"})

        assert result.platform_admins_created == ["alice"]
        assert result.platform_admins_granted == ["alice"]
        assert kc.created_with["alice"] == {
            "email": "alice@example.org", "first_name": "Alice", "last_name": "Doe",
            "temporary_password": "tmp-1", "temporary": True, "email_verified": True,
        }
        assert kc.users["alice"] == {"platform-admin"}
        assert result.changed

    @pytest.mark.asyncio
    async def test_without_a_password_the_run_is_refused_before_any_write(self, tmp_path):
        """@verifies REQ-0022"""
        kc = realm()
        with pytest.raises(PlatformDeclarationError, match="CELINE_KEYCLOAK_PLATFORM_ADMIN_PASSWORD"):
            await converge(kc, declared(tmp_path, ALICE_YAML))
        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_a_dry_run_reports_it_and_writes_nothing(self, tmp_path):
        """@verifies REQ-0022"""
        kc = realm()
        result = await converge(kc, declared(tmp_path, ALICE_YAML), dry_run=True, passwords={"alice": "t"})
        assert result.platform_admins_created == ["alice"]
        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_a_plain_username_is_still_only_reported(self, tmp_path):
        """@verifies REQ-0011"""
        kc = realm()
        result = await converge(kc, declared(tmp_path, "[carol]"), passwords={"carol": "t"})
        assert result.platform_admins_missing == ["carol"]
        assert result.platform_admins_created == []
        assert not result.changed


class TestAnExistingAccount:
    @pytest.mark.asyncio
    async def test_is_granted_and_never_rewritten(self, tmp_path):
        """@verifies REQ-0022"""
        kc = realm(users={"alice": set()}, user_attrs={"alice": {"email": "alice@example.org"}})
        result = await converge(kc, declared(tmp_path, ALICE_YAML), passwords={"alice": "t"})

        assert result.platform_admins_created == []
        assert result.platform_admins_granted == ["alice"]
        assert "alice" not in kc.created_with
        assert [w for w in kc.writes if w[0] == "user"] == []

    @pytest.mark.asyncio
    async def test_a_disabled_one_is_reported_and_stays_disabled(self, tmp_path):
        """@verifies REQ-0022"""
        kc = realm(users={"alice": {"platform-admin"}},
                   user_attrs={"alice": {"enabled": False, "email": "alice@example.org"}})
        result = await converge(kc, declared(tmp_path, ALICE_YAML), passwords={"alice": "t"})

        assert result.platform_admins_disabled == ["alice"]
        assert kc.writes == []
        assert not result.changed

    @pytest.mark.asyncio
    async def test_another_email_is_reported_and_kept(self, tmp_path):
        """@verifies REQ-0022"""
        kc = realm(users={"alice": {"platform-admin"}}, user_attrs={"alice": {"email": "old@example.org"}})
        result = await converge(kc, declared(tmp_path, ALICE_YAML), passwords={"alice": "t"})

        assert result.platform_admins_email_differs == ["alice"]
        assert kc.writes == []


# ---------------------------------------------------------------------------
# Where the temporary password comes from
# ---------------------------------------------------------------------------


class TestTheTemporaryPassword:
    def test_per_account(self):
        env = {"CELINE_KEYCLOAK_PLATFORM_ADMIN_PASSWORD_ALICE_DOE": "p"}
        assert platform_admin_password("alice.doe", environ=env) == "p"

    def test_from_the_template(self):
        env = {"CELINE_KEYCLOAK_PLATFORM_ADMIN_PASSWORD_TEMPLATE": "{username}.x+1"}
        assert platform_admin_password("alice", environ=env) == "alice.x+1"

    def test_the_account_wins_over_the_template(self):
        env = {"CELINE_KEYCLOAK_PLATFORM_ADMIN_PASSWORD_TEMPLATE": "{username}.x",
               "CELINE_KEYCLOAK_PLATFORM_ADMIN_PASSWORD_ALICE": "own"}
        assert platform_admin_password("alice", environ=env) == "own"

    def test_neither_is_none(self):
        assert platform_admin_password("alice", environ={}) is None

    def test_a_template_without_the_username_is_refused(self):
        """One password for every account is not a temporary password, it is a shared one."""
        env = {"CELINE_KEYCLOAK_PLATFORM_ADMIN_PASSWORD_TEMPLATE": "same-for-all"}
        with pytest.raises(ValueError, match="{username}"):
            platform_admin_password("alice", environ=env)
