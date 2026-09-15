"""What the realm import gave a realm, and what gives it now (requester, 2026-09-14).

The imports created three things nothing else declared, so a realm `bootstrap` creates had
none of them:

- the **`oauth2_proxy` client**, the browser login: now declared in `clients.yaml`, with a
  `browser:` block `sync` manages;
- an **operator realm admin**, in every environment: now `bootstrap`, from
  `CELINE_KEYCLOAK_REALM_ADMIN_*`;
- the **four development users**: now `seed-dev-users`, which refuses outside dev.

Keycloak is faked. The run against a real 26.7.3 is in the plan's work directory.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

from celine.policies.cli.keycloak.client import CurrentState, KeycloakAdminClient
from celine.policies.cli.keycloak.commands import seed_dev_users as seed_module
from celine.policies.cli.keycloak.models import BrowserLogin, ClientConfig, KeycloakConfig
from celine.policies.cli.keycloak.platform import PlatformDeclarationError, load_platform
from celine.policies.cli.keycloak.settings import KeycloakSettings, RealmAdminSettings
from celine.policies.cli.keycloak.sync import _client_needs_update, compute_sync_plan
from celine.policies.cli.main import app
from test_platform_declaration import PLATFORM_YAML, FakeRealm

REPO_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


# ---------------------------------------------------------------------------
# oauth2_proxy: a declared browser client
# ---------------------------------------------------------------------------

PROXY = ClientConfig(
    client_id="oauth2_proxy",
    secret="s",
    service_account_enabled=False,
    browser=BrowserLogin(
        redirect_uris=["http://sso.x/*", "http://webapp.x/*"],
        implicit_flow=True,
        direct_access_grants=True,
        access_token_lifespan=1800,
    ),
)


def as_keycloak(config: ClientConfig, **overrides) -> dict:
    rep = {
        "id": f"uuid-{config.client_id}",
        "clientId": config.client_id,
        "name": config.name,
        "description": config.description,
        "serviceAccountsEnabled": config.service_account_enabled,
        **config.login_representation(),
    }
    rep["attributes"] = {"client.secret.creation.time": "1", **rep.get("attributes", {})}
    rep.update(overrides)
    return rep


class TestABrowserClientConverges:
    def test_a_matching_client_needs_nothing_whatever_the_order_or_extra_attributes(self):
        current = as_keycloak(PROXY, redirectUris=["http://webapp.x/*", "http://sso.x/*"])
        assert _client_needs_update(PROXY, current) is False

    @pytest.mark.parametrize(
        "overrides",
        [
            {"redirectUris": ["http://sso.x/*"]},
            {"webOrigins": ["http://other"]},
            {"standardFlowEnabled": False},
            {"directAccessGrantsEnabled": False},
            {"attributes": {"access.token.lifespan": "300"}},
        ],
    )
    def test_each_managed_key_is_compared(self, overrides):
        assert _client_needs_update(PROXY, as_keycloak(PROXY, **overrides)) is True

    def test_a_service_client_s_flows_are_still_not_compared(self):
        """Comparing them now would plan an update of every client ever hand-edited."""
        service = ClientConfig(client_id="svc-x")
        current = as_keycloak(service, standardFlowEnabled=True, redirectUris=["http://a/*"])
        assert _client_needs_update(service, current) is False

    def test_a_service_client_is_still_created_with_every_flow_off(self):
        assert ClientConfig(client_id="svc-x").login_representation() == {
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
        }

    def test_declaring_the_proxy_does_not_plan_its_audience_mappers_away(self):
        """The generic loop would give it no audiences; the proxy block owns them."""
        svc = ClientConfig(client_id="svc-dataset-api", scopes_prefix="dataset")
        config = KeycloakConfig(oauth2_proxy_client="oauth2_proxy", clients=[PROXY, svc])
        current = CurrentState(
            clients={c.client_id: as_keycloak(c) for c in config.clients},
            client_audience_mappers={
                "oauth2_proxy": {"svc-dataset-api": "m1", "oauth2_proxy": "m2"},
                "svc-dataset-api": {},
            },
        )

        plan = compute_sync_plan(config, current)

        assert [a for a in plan.audience_mappers_to_remove if a.client_id == "oauth2_proxy"] == []
        assert [a for a in plan.audience_mappers_to_add if a.client_id == "oauth2_proxy"] == []

    @pytest.mark.asyncio
    async def test_an_update_merges_attributes_and_turns_the_flows_on(self):
        kc = KeycloakAdminClient(KeycloakSettings())
        kc.get_client = AsyncMock(
            return_value={"id": "u", "attributes": {"keep.me": "1"}, "standardFlowEnabled": False}
        )
        kc._put = AsyncMock()

        await kc.update_client("u", "oauth2_proxy", login=PROXY.login_representation())

        payload = kc._put.await_args.kwargs["json"]
        assert payload["attributes"] == {"keep.me": "1", "access.token.lifespan": "1800"}
        assert payload["standardFlowEnabled"] is True
        assert payload["redirectUris"] == ["http://sso.x/*", "http://webapp.x/*"]


# ---------------------------------------------------------------------------
# The operator realm admin
# ---------------------------------------------------------------------------


class AdminRealm(FakeRealm):
    def __init__(self, *args, users: dict[str, set[str]] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.users = {name: set(g) for name, g in (users or {}).items()}
        self.created_with: dict[str, dict] = {}

    async def get_user_by_username(self, username):
        return {"id": f"uid-{username}", "username": username} if username in self.users else None

    async def get_user_groups(self, user_id):
        return [{"path": p} for p in self.users[user_id.removeprefix("uid-")]]

    async def ensure_user(self, username, **kwargs):
        self.writes.append(("user", username))
        self.created_with[username] = kwargs
        self.users[username] = set()
        return f"uid-{username}", True

    async def add_user_to_group(self, user_id, group_id):
        self.writes.append(("member", user_id, group_id))
        self.users[user_id.removeprefix("uid-")].add(group_id.removeprefix("id"))


@pytest.fixture
def admin_env(monkeypatch):
    def set_env(**values):
        base = {"USERNAME": "celine-admin", "EMAIL": "admin@celine.test", "PASSWORD": "pw"}
        base.update(values)
        for key, value in base.items():
            monkeypatch.setenv(f"CELINE_KEYCLOAK_REALM_ADMIN_{key}", value)
        return RealmAdminSettings()

    return set_env


async def converge(kc, *, realm_admin, dry_run=False):
    from celine.policies.cli.keycloak.platform import converge_platform

    return await converge_platform(
        kc, load_platform(PLATFORM_YAML), brute_force_protected=False, dry_run=dry_run,
        realm_admin=realm_admin,
    )


class TestBootstrapCreatesTheRealmAdmin:
    @pytest.mark.asyncio
    async def test_unset_nobody_is_created(self):
        kc = AdminRealm()
        result = await converge(kc, realm_admin=RealmAdminSettings())
        assert result.realm_admin_created is None
        assert not [w for w in kc.writes if w[0] in ("user", "member")]

    @pytest.mark.asyncio
    async def test_it_is_created_verified_with_a_permanent_password_in_its_group(self, admin_env):
        kc = AdminRealm()

        result = await converge(kc, realm_admin=admin_env())

        assert result.realm_admin_created == "celine-admin"
        assert kc.users["celine-admin"] == {"/admins"}
        made = kc.created_with["celine-admin"]
        assert made["temporary_password"] == "pw" and made["temporary"] is False
        assert made["email_verified"] is True
        # Without both names Keycloak refuses the sign-in: "Account is not fully set up".
        assert made["first_name"] == "Celine" and made["last_name"] == "Admin"

    @pytest.mark.asyncio
    async def test_empty_names_are_refused_before_any_write(self, admin_env):
        kc = AdminRealm()
        with pytest.raises(PlatformDeclarationError, match="LAST_NAME"):
            await converge(kc, realm_admin=admin_env(LAST_NAME=""))
        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_a_second_run_changes_nothing_and_never_resends_the_password(self, admin_env):
        kc = AdminRealm()
        await converge(kc, realm_admin=admin_env())
        writes = len(kc.writes)

        second = await converge(kc, realm_admin=admin_env(PASSWORD="another"))

        assert not second.changed
        assert len(kc.writes) == writes

    @pytest.mark.asyncio
    async def test_an_existing_account_outside_the_group_is_put_back(self, admin_env):
        kc = AdminRealm(users={"celine-admin": set()})

        result = await converge(kc, realm_admin=admin_env(PASSWORD=""))

        assert result.realm_admin_created is None
        assert result.realm_admin_group_added == ("celine-admin", "/admins")
        assert kc.users["celine-admin"] == {"/admins"}
        assert ("user", "celine-admin") not in kc.writes

    @pytest.mark.asyncio
    async def test_creating_it_without_a_password_is_refused_before_any_write(self, admin_env):
        kc = AdminRealm()
        with pytest.raises(PlatformDeclarationError, match="REALM_ADMIN_PASSWORD"):
            await converge(kc, realm_admin=admin_env(PASSWORD=""))
        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_a_group_nobody_declares_is_refused(self, admin_env):
        kc = AdminRealm()
        with pytest.raises(PlatformDeclarationError, match="/operators"):
            await converge(kc, realm_admin=admin_env(GROUP="/operators"))
        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_a_dry_run_reports_and_writes_nothing(self, admin_env):
        kc = AdminRealm()
        result = await converge(kc, realm_admin=admin_env(), dry_run=True)
        assert result.realm_admin_created == "celine-admin" and kc.writes == []


# ---------------------------------------------------------------------------
# seed-dev-users
# ---------------------------------------------------------------------------


class TestTheDevelopmentUsers:
    def test_the_shipped_file_is_the_import_s_four_users(self):
        import json

        users = seed_module.load_dev_users(REPO_ROOT / "config/keycloak/dev-users.yaml")
        imported = json.loads((REPO_ROOT / "config/keycloak/import/realm-celine.json").read_text())
        assert {(u["username"], u["group"]) for u in users} == {
            (u["username"], u["groups"][0]) for u in imported["users"]
        }

    def test_every_group_is_a_role_group_bootstrap_creates(self):
        users = seed_module.load_dev_users(REPO_ROOT / "config/keycloak/dev-users.yaml")
        declared = {g.path for g in load_platform(PLATFORM_YAML).role_groups}
        assert {u["group"] for u in users} <= declared

    @pytest.mark.parametrize("env", [None, "prod", "staging"])
    def test_it_refuses_outside_development(self, monkeypatch, env):
        if env:
            monkeypatch.setenv("ENV", env)
        monkeypatch.setattr(seed_module, "KeycloakAdminClient", lambda *a, **k: pytest.fail("reached Keycloak"))

        result = runner.invoke(app, ["keycloak", "seed-dev-users"])

        assert result.exit_code == 1
        assert "development realm" in result.output

    @pytest.mark.parametrize(
        "text",
        ["users: []", "users:\n  - username: a\n    group: /admins", "users:\n  - username: a\n    password: a\n    group: admins", "users:\n  - {username: a, password: a, group: /admins, role: x}"],
    )
    def test_a_bad_file_is_refused(self, tmp_path, text):
        path = tmp_path / "u.yaml"
        path.write_text(text)
        with pytest.raises(ValueError):
            seed_module.load_dev_users(path)

    @pytest.mark.asyncio
    async def test_it_creates_then_changes_nothing(self, monkeypatch):
        kc = AdminRealm(groups={"/admins": {"admin"}, "/viewers": {"viewer"}})
        kc.authenticate = AsyncMock()
        monkeypatch.setattr(seed_module, "KeycloakAdminClient", lambda *a, **k: _Ctx(kc))
        users = [
            {"username": "admin", "password": "admin", "group": "/admins"},
            {"username": "viewer", "password": "viewer", "group": "/viewers"},
        ]

        created, joined = await seed_module._async_seed(KeycloakSettings(), users, dry_run=False)
        again = await seed_module._async_seed(KeycloakSettings(), users, dry_run=False)

        assert created == ["admin", "viewer"] and len(joined) == 2
        assert again == ([], [])
        assert kc.users == {"admin": {"/admins"}, "viewer": {"/viewers"}}

    @pytest.mark.asyncio
    async def test_a_missing_group_is_refused_before_any_write(self, monkeypatch):
        kc = AdminRealm(groups={"/admins": {"admin"}})
        kc.authenticate = AsyncMock()
        monkeypatch.setattr(seed_module, "KeycloakAdminClient", lambda *a, **k: _Ctx(kc))
        users = [
            {"username": "admin", "password": "admin", "group": "/admins"},
            {"username": "viewer", "password": "viewer", "group": "/viewers"},
        ]

        with pytest.raises(Exception, match="keycloak bootstrap"):
            await seed_module._async_seed(KeycloakSettings(), users, dry_run=False)

        assert kc.writes == []


class _Ctx:
    def __init__(self, kc):
        self.kc = kc

    async def __aenter__(self):
        return self.kc

    async def __aexit__(self, *exc):
        return False


class TestOneSyncGivesANewProxyItsClaims:
    """A fresh realm: `sync` creates oauth2_proxy, so the claim scopes are assigned after."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("created", "expected_calls"), [(["oauth2_proxy"], 2), ([], 1)])
    async def test_the_claim_scopes_are_ensured_again_only_when_this_run_created_the_proxy(
        self, monkeypatch, created, expected_calls
    ):
        import celine.policies.cli.keycloak.commands.sync as sync_command
        from celine.policies.cli.keycloak.sync import SyncResult

        calls = []

        class Kc:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def authenticate(self):
                pass

            async def ensure_realm_claim_scopes(self, proxy):
                calls.append(proxy)
                return True

            async def fetch_current_state(self):
                return CurrentState()

            async def fetch_admin_permission_state(self, *a):
                pass

        async def apply(**kwargs):
            return SyncResult(clients_created=list(created))

        monkeypatch.setattr(sync_command, "KeycloakAdminClient", lambda *a, **k: Kc())
        monkeypatch.setattr(sync_command, "apply_sync_plan", apply)
        config = KeycloakConfig(oauth2_proxy_client="oauth2_proxy", clients=[PROXY])

        await sync_command._async_sync(KeycloakSettings(), config, False, False)

        assert calls == ["oauth2_proxy"] * expected_calls
