"""What the realm import gave a realm, and what gives it now (requester, 2026-09-14).

The imports created three things nothing else declared, so a realm `bootstrap` creates had
none of them:

- the **`oauth2_proxy` client**, the browser login: now declared in `clients.yaml`, with a
  `browser:` block `sync` manages;
- an **operator realm admin**, in every environment: now `bootstrap`, from
  `CELINE_KEYCLOAK_REALM_ADMIN_*`;
- the **development users**: now `seed-dev-users`, which refuses outside dev. Since
  ADR-0012 they are a `platform-admin` and two organization users, in no realm group.

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
    default_scopes=["roles"],
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
    """A converged realm (the platform role exists) whose users are given as name -> roles."""

    def __init__(self, *args, users: dict[str, set[str]] | None = None, **kwargs):
        kwargs.setdefault("roles", {"platform-admin"})
        super().__init__(*args, users=users, **kwargs)


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
        assert not [w for w in kc.writes if w[0] in ("user", "grant")]

    @pytest.mark.asyncio
    async def test_it_is_created_verified_with_a_permanent_password_holding_platform_admin(self, admin_env):
        """@verifies REQ-0011"""
        kc = AdminRealm()

        result = await converge(kc, realm_admin=admin_env())

        assert result.realm_admin_created == "celine-admin"
        assert result.platform_admins_granted == ["celine-admin"]
        assert kc.users["celine-admin"] == {"platform-admin"}
        made = kc.created_with["celine-admin"]
        assert made["temporary_password"] == "pw" and made["temporary"] is False
        assert made["email_verified"] is True
        # Without both names Keycloak refuses the sign-in: "Account is not fully set up".
        assert made["first_name"] == "Celine" and made["last_name"] == "Admin"

    @pytest.mark.asyncio
    async def test_on_a_new_realm_the_role_exists_before_the_admin_is_granted_it(self, admin_env):
        """@verifies REQ-0011"""
        kc = AdminRealm(roles=set())

        await converge(kc, realm_admin=admin_env())

        order = [w[0] for w in kc.writes if w[0] in ("role", "user", "grant")]
        assert order == ["role", "user", "grant"]

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
    async def test_an_existing_account_without_the_role_is_given_it(self, admin_env):
        """@verifies REQ-0011"""
        kc = AdminRealm(users={"celine-admin": set()})

        result = await converge(kc, realm_admin=admin_env(PASSWORD=""))

        assert result.realm_admin_created is None
        assert result.platform_admins_granted == ["celine-admin"]
        assert kc.users["celine-admin"] == {"platform-admin"}
        assert ("user", "celine-admin") not in kc.writes

    @pytest.mark.asyncio
    async def test_an_old_realm_admin_in_admins_ends_with_the_role_and_no_group(self, admin_env):
        """The state every deployed realm is in: the operator account in `/admins`.

        @verifies REQ-0011
        @verifies REQ-0012
        """
        kc = AdminRealm(
            roles={"admin"}, groups={"/admins": {"admin"}}, users={"celine-admin": set()}
        )

        await converge(kc, realm_admin=admin_env(PASSWORD=""))

        assert kc.groups == {}
        assert kc.roles == {"platform-admin"}
        assert kc.users["celine-admin"] == {"platform-admin"}

    @pytest.mark.asyncio
    async def test_creating_it_without_a_password_is_refused_before_any_write(self, admin_env):
        kc = AdminRealm()
        with pytest.raises(PlatformDeclarationError, match="REALM_ADMIN_PASSWORD"):
            await converge(kc, realm_admin=admin_env(PASSWORD=""))
        assert kc.writes == []

    def test_a_group_setting_no_longer_exists(self, admin_env):
        """Realm groups carry no authority: nothing to put the account in.

        @verifies REQ-0011
        """
        assert "group" not in RealmAdminSettings.model_fields

    @pytest.mark.asyncio
    async def test_a_dry_run_reports_and_writes_nothing(self, admin_env):
        kc = AdminRealm()
        result = await converge(kc, realm_admin=admin_env(), dry_run=True)
        assert result.realm_admin_created == "celine-admin" and kc.writes == []


# ---------------------------------------------------------------------------
# seed-dev-users
# ---------------------------------------------------------------------------


class OrgRealm(AdminRealm):
    """AdminRealm plus organizations and their groups, as seed-dev-users reads them."""

    def __init__(self, *args, orgs: dict[str, set[str]] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        # alias -> its group names; memberships as (alias, group, username)
        self.orgs = {alias: set(groups) for alias, groups in (orgs or {}).items()}
        self.memberships: set[tuple[str, str, str]] = set()

    async def get_organization_by_alias(self, alias):
        return {"id": f"org-{alias}", "alias": alias} if alias in self.orgs else None

    async def get_org_group_by_name(self, org_id, name):
        alias = org_id.removeprefix("org-")
        return {"id": f"{alias}/{name}", "name": name} if name in self.orgs[alias] else None

    async def is_user_in_org_group(self, org_id, group_id, user_id):
        alias, group = group_id.split("/")
        return (alias, group, user_id.removeprefix("uid-")) in self.memberships

    async def ensure_user_in_organization(self, org_id, user_id):
        self.writes.append(("org-member", org_id, user_id))
        return True

    async def ensure_user_in_org_group(self, org_id, group_id, user_id):
        alias, group = group_id.split("/")
        self.writes.append(("org-group", alias, group, user_id))
        self.memberships.add((alias, group, user_id.removeprefix("uid-")))
        return True


DEV_USERS = REPO_ROOT / "config/keycloak/dev-users.yaml"


class TestTheDevelopmentUsers:
    def test_the_shipped_file_has_a_platform_admin_an_org_admin_and_an_org_viewer(self):
        """ADR-0012: one platform admin; an organization admin who is NOT one; a member.

        @verifies REQ-0011
        """
        users = {u["username"]: u for u in seed_module.load_dev_users(DEV_USERS)}
        assert users["admin"]["realm_roles"] == ["platform-admin"]
        assert users["org-admin"]["realm_roles"] == []
        assert users["org-admin"]["organizations"] == {"example_rec": "admins"}
        assert users["org-viewer"]["realm_roles"] == []
        assert users["org-viewer"]["organizations"] == {"example_rec": "viewers"}

    def test_the_dev_overlay_declares_exactly_the_dev_platform_admins(self):
        """The local realm's declared list: generic dev users only, the ones that hold the role.

        @verifies REQ-0011
        """
        users = seed_module.load_dev_users(DEV_USERS)
        declaration = load_platform(PLATFORM_YAML, [REPO_ROOT / "config/keycloak/platform.dev.yaml"])
        assert declaration.platform_admins == [
            u["username"] for u in users if "platform-admin" in u["realm_roles"]
        ] == ["admin"]

    def test_the_import_s_users_are_seeded_users_with_the_same_realm_roles(self):
        """The import carries the users it can (no organization exists at import time)."""
        import json

        users = {u["username"]: u for u in seed_module.load_dev_users(DEV_USERS)}
        imported = json.loads((REPO_ROOT / "config/keycloak/import/realm-celine.json").read_text())
        for user in imported["users"]:
            assert "groups" not in user
            assert user.get("realmRoles", []) == users[user["username"]]["realm_roles"]

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
        [
            "users: []",
            "users:\n  - username: a\n    realm_roles: [platform-admin]",
            "users:\n  - {username: a, password: a, group: /admins}",
            "users:\n  - {username: a, password: a, realm_roles: [admin]}",
            "users:\n  - {username: a, password: a, organizations: {example_rec: owners}}",
            "users:\n  - {username: a, password: a, role: x}",
        ],
    )
    def test_a_bad_file_is_refused(self, tmp_path, text):
        path = tmp_path / "u.yaml"
        path.write_text(text)
        with pytest.raises(ValueError):
            seed_module.load_dev_users(path)

    @pytest.mark.asyncio
    async def test_it_creates_then_changes_nothing(self, monkeypatch):
        """@verifies REQ-0011"""
        kc = OrgRealm(orgs={"example_rec": {"admins", "viewers"}})
        kc.authenticate = AsyncMock()
        monkeypatch.setattr(seed_module, "KeycloakAdminClient", lambda *a, **k: _Ctx(kc))
        users = seed_module.load_dev_users(DEV_USERS)
        users[0]["organizations"].pop("example_dso")

        created, joined = await seed_module._async_seed(KeycloakSettings(), users, dry_run=False)
        again = await seed_module._async_seed(KeycloakSettings(), users, dry_run=False)

        assert created == ["admin", "org-admin", "org-viewer"]
        assert ("admin", "realm role platform-admin") in joined
        assert again == ([], [])
        assert kc.users == {"admin": {"platform-admin"}, "org-admin": set(), "org-viewer": set()}
        assert kc.memberships == {
            ("example_rec", "admins", "admin"),
            ("example_rec", "admins", "org-admin"),
            ("example_rec", "viewers", "org-viewer"),
        }

    @pytest.mark.asyncio
    async def test_an_existing_user_gains_what_it_lacks(self, monkeypatch):
        kc = OrgRealm(orgs={"example_rec": {"admins"}}, users={"admin": set()})
        kc.authenticate = AsyncMock()
        monkeypatch.setattr(seed_module, "KeycloakAdminClient", lambda *a, **k: _Ctx(kc))
        users = [{"username": "admin", "password": "admin", "realm_roles": ["platform-admin"],
                  "organizations": {"example_rec": "admins"}}]

        created, joined = await seed_module._async_seed(KeycloakSettings(), users, dry_run=False)

        assert created == []
        assert joined == [("admin", "realm role platform-admin"), ("admin", "example_rec/admins")]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("kc_kwargs", "match"),
        [
            (dict(roles=set(), orgs={"example_rec": {"admins", "viewers"}}), "keycloak bootstrap"),
            (dict(orgs={}), "organization example_rec"),
            (dict(orgs={"example_rec": {"viewers"}}), "no group admins"),
        ],
    )
    async def test_anything_missing_is_refused_before_any_write(self, monkeypatch, kc_kwargs, match):
        kc = OrgRealm(**kc_kwargs)
        kc.authenticate = AsyncMock()
        monkeypatch.setattr(seed_module, "KeycloakAdminClient", lambda *a, **k: _Ctx(kc))
        users = [
            {"username": "admin", "password": "admin", "realm_roles": ["platform-admin"],
             "organizations": {"example_rec": "admins"}},
        ]

        with pytest.raises(Exception, match=match):
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

            async def retire_groups_claim(self, remove=True):
                return []

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
