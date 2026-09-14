"""Each command writes one level. The platform level is `bootstrap`'s alone.

Before plan each-cli-command-owns-one-level, `sync-orgs` and `sync-users` turned
Organizations on and created the role groups, and `sync` turned fine-grained admin
permissions on, each as a side effect of a run meant for something else. A dry run of a
user import showed platform changes nobody asked for, and a change to one of those writes
had to be made in three places. What is guarded here:

- the organization and user commands, and `sync`, **check** the platform and refuse,
  naming `bootstrap`, instead of writing it, and they refuse before their first write;
- no module but `platform.py` writes the realm representation;
- `bootstrap` prints the admin CLI client's secret only in a non-production environment,
  and says where the secrets file really is;
- `set-password` runs only against a development realm.

Keycloak is faked throughout. What Keycloak accepts is the plan's by-hand run.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

import celine.policies.cli.keycloak.commands.bootstrap as bootstrap_module
import celine.policies.cli.keycloak.commands.sync as sync_command_module
import celine.policies.cli.keycloak.commands.sync_orgs as sync_orgs_module
import celine.policies.cli.keycloak.commands.sync_users as sync_users_module
from celine.policies.cli.keycloak.client import (
    REALM_CLAIM_SCOPES,
    CurrentState,
    KeycloakAdminClient,
)
from celine.policies.cli.keycloak.commands._utils import ClientsNotSynced
from celine.policies.cli.keycloak.commands.sync_users import CommunityPlan
from celine.policies.cli.keycloak.models import (
    AdminGroupPermission,
    AdminPermissions,
    ClientConfig,
    KeycloakConfig,
)
from celine.policies.cli.keycloak.platform import PlatformNotReady, PlatformResult
from celine.policies.cli.keycloak.settings import KeycloakSettings, SyncUsersSettings
from celine.policies.cli.main import app

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src" / "celine"
PLATFORM_YAML = REPO_ROOT / "platform.yaml"

runner = CliRunner()

#: Every Admin API call that writes the platform level.
PLATFORM_WRITES = {
    "update_realm_settings",
    "create_realm_role",
    "add_group_realm_role",
    "create_group",
    "ensure_group",
}

#: The clients-level writes the organization and user commands used to repeat (Phase 3).
CLIENT_LEVEL_WRITES = {"ensure_realm_claim_scopes", "ensure_audience_mapper"}


class RecordingKeycloak:
    """Answers any awaited call, records its name, and returns what `answers` says."""

    def __init__(self, **answers: Any):
        self.calls: list[str] = []
        self._answers = {
            "get_realm_settings": {"organizationsEnabled": True},
            "list_client_scopes": [{"name": n} for n in REALM_CLAIM_SCOPES],
            "get_admin_permissions_client_uuid": "uuid-ap",
            "get_organization_by_alias": None,
            "ensure_organization": ("org-1", True),
            "ensure_org_group": ("orggrp-1", True),
            "ensure_realm_claim_scopes": False,
            "get_client_by_client_id": None,
            "get_user_by_username": None,
            "get_group_by_path": None,
            "ensure_user_in_organization": True,
            "fetch_current_state": None,
            **answers,
        }

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)

        async def call(*args, **kwargs):
            self.calls.append(name)
            if name == "ensure_user":
                return f"uuid-{args[0] if args else kwargs.get('username')}", True
            return self._answers.get(name)

        return call


def install(monkeypatch, module, kc: RecordingKeycloak) -> RecordingKeycloak:
    monkeypatch.setattr(module, "KeycloakAdminClient", lambda *a, **k: kc)
    return kc


@pytest.fixture
def kc_settings() -> KeycloakSettings:
    return KeycloakSettings(base_url="http://kc.internal", realm="celine", admin_client_secret="s")


OWNERS = [{"id": "set-distribuzione", "name": "SET", "organization": {"create": True, "role": "dso"}}]
COMMUNITY = CommunityPlan(
    community={"id": "greenland", "name": "Greenland", "description": ""},
    participants=[{"key": "gl-1", "user_id": "gl-1"}],
    operators=[],
)


# ---------------------------------------------------------------------------
# The organization and user commands
# ---------------------------------------------------------------------------


class TestSyncOrgsChecksThePlatform:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("dry_run", [False, True])
    async def test_it_makes_no_platform_write(self, monkeypatch, kc_settings, dry_run):
        kc = install(monkeypatch, sync_orgs_module, RecordingKeycloak())

        _, _, errors = await sync_orgs_module._async_sync_orgs(
            kc_settings=kc_settings, org_owners=OWNERS, dry_run=dry_run
        )

        assert errors == []
        assert not (PLATFORM_WRITES | CLIENT_LEVEL_WRITES) & set(kc.calls)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dry_run", [False, True])
    async def test_it_refuses_a_realm_without_organizations_before_any_write(
        self, monkeypatch, kc_settings, dry_run
    ):
        kc = install(
            monkeypatch,
            sync_orgs_module,
            RecordingKeycloak(get_realm_settings={"organizationsEnabled": False}),
        )

        with pytest.raises(PlatformNotReady, match="keycloak bootstrap"):
            await sync_orgs_module._async_sync_orgs(
                kc_settings=kc_settings, org_owners=OWNERS, dry_run=dry_run
            )

        assert kc.calls == ["authenticate", "get_realm_settings"]


class TestSyncUsersChecksThePlatform:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("dry_run", [False, True])
    async def test_it_makes_no_platform_write(self, monkeypatch, kc_settings, dry_run):
        kc = install(monkeypatch, sync_users_module, RecordingKeycloak())

        await sync_users_module._async_sync_users(
            kc_settings=kc_settings,
            sync_settings=SyncUsersSettings(groups=[], temp_password="pw", dry_run=dry_run),
            communities=[COMMUNITY],
        )

        assert "get_realm_settings" in kc.calls
        assert not (PLATFORM_WRITES | CLIENT_LEVEL_WRITES) & set(kc.calls)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dry_run", [False, True])
    async def test_it_refuses_a_realm_without_organizations_before_any_write(
        self, monkeypatch, kc_settings, dry_run
    ):
        kc = install(
            monkeypatch,
            sync_users_module,
            RecordingKeycloak(get_realm_settings={"organizationsEnabled": False}),
        )

        with pytest.raises(PlatformNotReady, match="organizationsEnabled"):
            await sync_users_module._async_sync_users(
                kc_settings=kc_settings,
                sync_settings=SyncUsersSettings(groups=[], temp_password="pw", dry_run=dry_run),
                communities=[COMMUNITY],
            )

        assert kc.calls == ["authenticate", "get_realm_settings"]


class TestClaimScopesHaveOneWriter:
    """Phase 3: `sync` converges the realm claim scopes; the others check they exist."""

    MISSING = [{"name": "organization"}, {"name": "groups"}]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dry_run", [False, True])
    async def test_sync_orgs_refuses_without_them_naming_sync(self, monkeypatch, kc_settings, dry_run):
        kc = install(monkeypatch, sync_orgs_module, RecordingKeycloak(list_client_scopes=self.MISSING))

        with pytest.raises(ClientsNotSynced, match="keycloak sync") as exc:
            await sync_orgs_module._async_sync_orgs(
                kc_settings=kc_settings, org_owners=OWNERS, dry_run=dry_run
            )

        assert "dataspace" in str(exc.value)
        assert kc.calls == ["authenticate", "get_realm_settings", "list_client_scopes"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dry_run", [False, True])
    async def test_sync_users_refuses_without_them_naming_sync(self, monkeypatch, kc_settings, dry_run):
        kc = install(monkeypatch, sync_users_module, RecordingKeycloak(list_client_scopes=self.MISSING))

        with pytest.raises(ClientsNotSynced, match="keycloak sync"):
            await sync_users_module._async_sync_users(
                kc_settings=kc_settings,
                sync_settings=SyncUsersSettings(groups=[], temp_password="pw", dry_run=dry_run),
                communities=[COMMUNITY],
            )

        assert kc.calls == ["authenticate", "get_realm_settings", "list_client_scopes"]

    def test_only_sync_calls_the_claim_scope_writer(self):
        callers = {
            str(path.relative_to(SRC))
            for path in SRC.rglob("*.py")
            if re.search(r"\.ensure_realm_claim_scopes\(", path.read_text())
        }
        assert callers == {"policies/cli/keycloak/commands/sync.py"}

    def test_the_organization_and_user_commands_write_no_audience_mapper(self):
        for module in (sync_orgs_module, sync_users_module):
            assert "ensure_audience_mapper" not in Path(module.__file__).read_text()


class TestSyncChecksAdminPermissions:
    CONFIG = KeycloakConfig(
        realm="celine",
        scopes=[],
        clients=[
            ClientConfig(
                client_id="svc-x",
                name="svc-x",
                admin_permissions=AdminPermissions(
                    groups=[AdminGroupPermission(path="/participants", scopes=["view-members"])]
                ),
            )
        ],
    )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dry_run", [False, True])
    async def test_a_declared_grant_on_a_realm_without_the_feature_refuses_before_any_write(
        self, monkeypatch, kc_settings, dry_run
    ):
        kc = install(
            monkeypatch,
            sync_command_module,
            RecordingKeycloak(get_admin_permissions_client_uuid=None),
        )

        with pytest.raises(PlatformNotReady, match="keycloak bootstrap"):
            await sync_command_module._async_sync(kc_settings, self.CONFIG, dry_run, False)

        assert kc.calls == ["authenticate", "get_admin_permissions_client_uuid"]

    @pytest.mark.asyncio
    async def test_a_declaration_without_grants_does_not_ask(self, monkeypatch, kc_settings):
        kc = install(
            monkeypatch, sync_command_module, RecordingKeycloak(fetch_current_state=CurrentState())
        )
        config = KeycloakConfig(realm="celine", scopes=[], clients=[])

        await sync_command_module._async_sync(kc_settings, config, True, False)

        assert "get_admin_permissions_client_uuid" not in kc.calls


class TestOneWriterOfTheRealmRepresentation:
    def test_no_command_turns_a_platform_feature_on_any_more(self):
        for name in (
            "ensure_organizations_enabled",
            "ensure_realm_groups",
            "ensure_admin_permissions_enabled",
        ):
            assert not hasattr(KeycloakAdminClient, name), name

    def test_only_the_platform_module_writes_the_realm_representation(self):
        writers = {
            str(path.relative_to(SRC))
            for path in SRC.rglob("*.py")
            if re.search(r"\bupdate_realm_settings\(", path.read_text())
            and path.name != "client.py"
        }
        assert writers == {"policies/cli/keycloak/platform.py"}


# ---------------------------------------------------------------------------
# bootstrap's output
# ---------------------------------------------------------------------------

SECRET = "s3cr3t-value-for-the-admin-cli"


@pytest.fixture
def fake_bootstrap(monkeypatch):
    run = AsyncMock(return_value=(PlatformResult(), (SECRET, True)))
    monkeypatch.setattr(bootstrap_module, "_async_bootstrap", run)
    return run


def invoke_bootstrap(*extra: str):
    return runner.invoke(
        app,
        ["keycloak", "bootstrap", str(PLATFORM_YAML), "-u", "http://kc.internal", *extra],
    )


class TestBootstrapKeepsTheSecretOutOfTheOutput:
    def test_outside_dev_the_secret_is_never_printed(self, tmp_path, fake_bootstrap):
        result = invoke_bootstrap(
            "--admin-user", "admin", "--admin-password", "admin",
            "--secrets-file", str(tmp_path / "s.yaml"),
        )

        assert result.exit_code == 0, result.output
        assert SECRET not in result.output
        assert "ENV=dev" in result.output
        assert SECRET in (tmp_path / "s.yaml").read_text()

    def test_in_dev_it_is_printed(self, monkeypatch, tmp_path, fake_bootstrap):
        monkeypatch.setenv("ENV", "dev")
        result = invoke_bootstrap(
            "--admin-user", "admin", "--admin-password", "admin",
            "--secrets-file", str(tmp_path / "s.yaml"),
        )

        assert result.exit_code == 0, result.output
        assert SECRET in result.output

    def test_the_secrets_file_named_is_the_one_used_when_it_comes_from_the_environment(
        self, monkeypatch, tmp_path, fake_bootstrap
    ):
        path = tmp_path / "from-env.yaml"
        monkeypatch.setenv("CELINE_KEYCLOAK_SECRETS_FILE", str(path))

        result = invoke_bootstrap("--admin-user", "admin", "--admin-password", "admin")

        assert result.exit_code == 0, result.output
        assert f"Secrets file: {path}" in result.output
        assert "Secrets file: None" not in result.output
        assert path.exists()

    def test_the_admin_user_wins_over_a_client_secret_in_the_environment(
        self, monkeypatch, tmp_path, fake_bootstrap
    ):
        monkeypatch.setenv("CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET", "stale")

        invoke_bootstrap(
            "--admin-user", "admin", "--admin-password", "admin",
            "--secrets-file", str(tmp_path / "s.yaml"),
        )

        settings = fake_bootstrap.await_args.kwargs["settings"]
        assert settings.admin_client_secret is None
        assert fake_bootstrap.await_args.kwargs["manage_admin_client"] is True


class TestBootstrapWithTheClientsOwnCredentials:
    def test_it_converges_the_platform_and_skips_the_admin_client(
        self, monkeypatch, tmp_path, fake_bootstrap
    ):
        monkeypatch.setenv("CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET", "from-env")

        result = invoke_bootstrap("--secrets-file", str(tmp_path / "s.yaml"))

        assert result.exit_code == 0, result.output
        assert fake_bootstrap.await_args.kwargs["manage_admin_client"] is False
        assert "Admin CLI client: skipped" in result.output
        assert not (tmp_path / "s.yaml").exists()

    def test_with_no_credentials_at_all_it_refuses(self, monkeypatch, tmp_path, fake_bootstrap):
        monkeypatch.chdir(tmp_path)

        result = invoke_bootstrap("--secrets-file", str(tmp_path / "absent.yaml"))

        assert result.exit_code == 1
        fake_bootstrap.assert_not_awaited()


class TestBootstrapRefusesABadDeclarationBeforeConnecting:
    def test_a_refused_key(self, tmp_path, fake_bootstrap):
        bad = tmp_path / "platform.yaml"
        bad.write_text("realm_settings:\n  verifyEmail: true\n")

        result = runner.invoke(
            app, ["keycloak", "bootstrap", str(bad), "--admin-user", "a", "--admin-password", "b"]
        )

        assert result.exit_code == 1
        assert "verifyEmail" in result.output
        fake_bootstrap.assert_not_awaited()


# ---------------------------------------------------------------------------
# set-password
# ---------------------------------------------------------------------------


class TestSetPasswordIsDevOnly:
    @pytest.fixture(autouse=True)
    def no_keycloak(self, monkeypatch):
        import celine.policies.cli.keycloak.commands.set_password as module

        def refuse(*a, **k):
            raise AssertionError("set-password reached Keycloak")

        monkeypatch.setattr(module, "KeycloakAdminClient", refuse)

    @pytest.mark.parametrize("env", [None, "prod", "staging", "typo"])
    def test_it_refuses_outside_a_development_environment(self, monkeypatch, env):
        if env:
            monkeypatch.setenv("ENV", env)

        result = runner.invoke(app, ["keycloak", "set-password", "alice", "pw"])

        assert result.exit_code == 1
        assert "development realm" in result.output
