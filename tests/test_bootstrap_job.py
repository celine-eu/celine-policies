"""What `bootstrap` gives a deployment job (plan each-cli-command-owns-one-level, Phase 4).

Decision 2 runs `bootstrap` as an init container or a Job that must be idempotent or fail:
it exports the realm before any write, applies, then runs a check that must find nothing
left to change, and outside dev it does not apply a plan that turns something off without
an explicit flag. The Kubernetes job, its lock and its storage are infra's. What is held
here is the command's half: the realm created when absent, the export before the first
write, `--check`'s exit code, and the destructive guard.

Keycloak is faked with `FakeRealm` from `test_platform_declaration`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import celine.policies.cli.keycloak.commands.bootstrap as bootstrap_module
from celine.policies.cli.keycloak.client import KeycloakError
from celine.policies.cli.keycloak.platform import (
    PlatformDeclarationError,
    SettingChange,
    destructive,
    load_platform,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.policies.cli.main import app
from test_platform_declaration import PLATFORM_YAML, FakeRealm

runner = CliRunner()


class JobRealm(FakeRealm):
    """`FakeRealm`, plus the calls `_async_bootstrap` makes around the converge."""

    def __init__(self, *args, exists: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self.exists = exists
        self.order: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def authenticate(self):
        pass

    async def realm_exists(self):
        return self.exists

    async def create_realm(self):
        self.order.append("create_realm")
        self.writes.append(("create_realm",))
        self.exists = True

    async def partial_export(self):
        self.order.append("export")
        return {"realm": "celine", "writes_before_export": len(self.writes)}

    async def update_realm_settings(self, settings):
        self.order.append("update")
        await super().update_realm_settings(settings)

    async def get_client_by_client_id(self, client_id):
        # the admin CLI client does not exist yet; account-console is FakeRealm's
        return await super().get_client_by_client_id(client_id) if client_id == "account-console" else None

    # The admin CLI client step, recorded and otherwise inert.
    async def create_client(self, **kwargs):
        self.writes.append(("client", kwargs["client_id"]))
        return "uuid-cli", "secret"

    async def ensure_default_scope(self, *args):
        pass

    async def ensure_realm_management_audience_mapper(self, *args):
        pass

    async def assign_realm_management_roles(self, *args):
        pass


def converged() -> dict:
    """A realm that already matches `platform.yaml`, brute force off."""
    settings = dict(load_platform(PLATFORM_YAML).realm_settings)
    settings["bruteForceProtected"] = False
    return settings


ROLES = {"admin", "manager", "editor", "viewer"}
GROUPS = {"/admins": {"admin"}, "/managers": {"manager"}, "/editors": {"editor"}, "/viewers": {"viewer"}}


@pytest.fixture
def settings() -> KeycloakSettings:
    return KeycloakSettings(base_url="http://kc.internal", realm="celine", admin_user="a", admin_password="b")


async def run(settings, kc, monkeypatch, **kwargs):
    monkeypatch.setattr(bootstrap_module, "KeycloakAdminClient", lambda *a, **k: kc)
    defaults = dict(
        declaration=load_platform(PLATFORM_YAML),
        client_id="celine-admin-cli",
        manage_admin_client=False,
        dry_run=False,
    )
    defaults.update(kwargs)
    return await bootstrap_module._async_bootstrap(settings=settings, **defaults)


class TestWhatIsDestructive:
    @pytest.mark.parametrize(
        ("current", "desired", "expected"),
        [
            (True, False, True),
            (False, True, False),
            (["it", "en", "es"], ["it", "en"], True),
            (["it", "en"], ["it", "en", "es"], False),
            (["es", "it", "en"], ["it", "en", "es"], False),
            (300, 3600, False),
            (3600, 300, False),
            ("keycloak", "rec", False),
            (None, True, False),
        ],
    )
    def test_off_or_narrowed_is_destructive_and_nothing_else_is(self, current, desired, expected):
        assert destructive(SettingChange("k", current, desired, "platform.yaml")) is expected


class TestTheDestructiveGuard:
    @pytest.mark.asyncio
    async def test_outside_dev_a_plan_turning_a_setting_off_is_refused_before_any_write(
        self, settings, monkeypatch
    ):
        realm = converged() | {"resetPasswordAllowed": False, "registrationAllowed": True}
        kc = JobRealm(realm, roles=ROLES, groups=GROUPS)

        with pytest.raises(PlatformDeclarationError, match="--allow-destructive") as exc:
            await run(settings, kc, monkeypatch, allow_destructive=False)

        assert "registrationAllowed" in str(exc.value)
        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_with_the_flag_it_is_applied(self, settings, monkeypatch):
        kc = JobRealm(converged() | {"registrationAllowed": True}, roles=ROLES, groups=GROUPS)

        await run(settings, kc, monkeypatch, allow_destructive=True)

        assert kc.realm["registrationAllowed"] is False

    @pytest.mark.asyncio
    async def test_a_plan_with_only_updates_needs_no_flag(self, settings, monkeypatch):
        kc = JobRealm(converged() | {"accessTokenLifespan": 300}, roles=ROLES, groups=GROUPS)

        await run(settings, kc, monkeypatch, allow_destructive=False)

        assert kc.realm["accessTokenLifespan"] == 3600

    def test_the_command_allows_it_in_dev_and_not_outside(self, monkeypatch):
        seen = {}

        async def fake(**kwargs):
            seen.update(kwargs)
            from celine.policies.cli.keycloak.platform import PlatformResult

            return PlatformResult(), ("", False)

        monkeypatch.setattr(bootstrap_module, "_async_bootstrap", fake)
        monkeypatch.setenv("CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET", "x")
        args = ["keycloak", "bootstrap", str(PLATFORM_YAML), "-u", "http://kc"]

        runner.invoke(app, args)
        assert seen["allow_destructive"] is False
        runner.invoke(app, [*args, "--allow-destructive"])
        assert seen["allow_destructive"] is True
        monkeypatch.setenv("ENV", "dev")
        runner.invoke(app, args)
        assert seen["allow_destructive"] is True


class TestTheRealmIsCreatedWhenAbsent:
    @pytest.mark.asyncio
    async def test_with_the_master_admin_it_is_created_then_converged(self, settings, monkeypatch):
        kc = JobRealm(exists=False)

        result, _ = await run(settings, kc, monkeypatch, manage_admin_client=True)

        assert result.realm_created
        assert kc.order[0] == "create_realm"
        assert kc.realm["organizationsEnabled"] is True
        assert kc.groups == GROUPS

    @pytest.mark.asyncio
    async def test_as_the_admin_cli_client_it_is_refused(self, settings, monkeypatch):
        kc = JobRealm(exists=False)

        with pytest.raises(KeycloakError, match="master admin"):
            await run(settings, kc, monkeypatch, manage_admin_client=False)

        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_a_dry_run_reports_it_and_creates_nothing(self, settings, monkeypatch):
        kc = JobRealm(exists=False)

        result, _ = await run(settings, kc, monkeypatch, manage_admin_client=True, dry_run=True)

        assert result.realm_created and result.changed
        assert kc.writes == []


class TestTheExportComesBeforeAnyWrite:
    @pytest.mark.asyncio
    async def test_it_is_written_first(self, settings, monkeypatch, tmp_path: Path):
        kc = JobRealm({"bruteForceProtected": False})
        path = tmp_path / "export.json"

        await run(settings, kc, monkeypatch, export=path)

        assert kc.order[0] == "export"
        assert json.loads(path.read_text()) == {"realm": "celine", "writes_before_export": 0}
        assert "update" in kc.order


class TestCheck:
    @pytest.fixture
    def result(self, monkeypatch):
        from celine.policies.cli.keycloak.platform import PlatformResult

        holder = {"result": PlatformResult()}

        async def fake(**kwargs):
            assert kwargs["dry_run"] is True
            return holder["result"], ("", False)

        monkeypatch.setattr(bootstrap_module, "_async_bootstrap", fake)
        monkeypatch.setenv("CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET", "x")
        return holder

    def invoke(self):
        return runner.invoke(app, ["keycloak", "bootstrap", str(PLATFORM_YAML), "-u", "http://kc", "--check"])

    def test_nothing_to_change_exits_0(self, result):
        outcome = self.invoke()
        assert outcome.exit_code == 0, outcome.output
        assert "Check passed" in outcome.output

    def test_a_change_exits_1(self, result):
        result["result"].settings = [SettingChange("resetPasswordAllowed", False, True, "platform.yaml")]
        assert self.invoke().exit_code == 1

    def test_the_smtp_password_alone_is_not_a_change(self, result):
        """Sent on every run and not comparable: the job's check must still pass."""
        result["result"].smtp_password_applied = True
        assert self.invoke().exit_code == 0
