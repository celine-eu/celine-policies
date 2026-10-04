"""The master realm, as `bootstrap` reaches and hardens it (REQ-0016, ADR-0014).

Against `keycloak_flows_fake.MasterFake`. What is held here: the order (sign in as the
bootstrap client first, the admin user only to create it, then the client for everything
else), the client converged to the configured secret and its roles, the hardening planned and
applied idempotently, the refusal of any other token, and dev left alone.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

import celine.policies.cli.keycloak.commands.bootstrap as bootstrap_module
from celine.policies.cli.keycloak.client import (
    ADMIN_USER,
    MASTER_CLIENT,
    REALM_CLIENT,
    AuthIdentity,
    KeycloakAdminClient,
    KeycloakAuthError,
)
from celine.policies.cli.keycloak.master import (
    CONFIGURE_TOTP,
    MasterHardeningRefused,
    apply_bootstrap_client,
    apply_master_hardening,
    plan_bootstrap_client,
    plan_master_hardening,
    require_bootstrap_client,
)
from celine.policies.cli.keycloak.admin_mfa import ADMIN_MFA_FLOW, desired_flow, flatten
from celine.policies.cli.keycloak.platform import destructive, load_platform
from celine.policies.cli.keycloak.settings import DEFAULT_BOOTSTRAP_CLIENT_ID, KeycloakSettings
from celine.policies.cli.main import app
from keycloak_flows_fake import MasterFake
from test_bootstrap_job import JobRealm, converged
from test_platform_declaration import PLATFORM_YAML

runner = CliRunner()
CLIENT = DEFAULT_BOOTSTRAP_CLIENT_ID
SECRET = "c" * 40
TUNING = {
    "permanentLockout": False, "failureFactor": 5, "waitIncrementSeconds": 60,
    "quickLoginCheckMilliSeconds": 1000, "minimumQuickLoginWaitSeconds": 60, "maxFailureWaitSeconds": 900,
}


def declaration():
    return load_platform(PLATFORM_YAML)


async def plan_client(master: MasterFake, *, as_client: bool = False):
    return await plan_bootstrap_client(master, client_id=CLIENT, secret=SECRET, signed_in_as_client=as_client)


# ---------------------------------------------------------------------------
# The secret is configured, and required outside dev
# ---------------------------------------------------------------------------


class TestTheSecretIsRequiredOutsideDev:
    def test_no_secret_outside_dev_is_a_problem(self):
        """@verifies REQ-0016"""
        problem = KeycloakSettings().bootstrap_secret_problem()
        assert problem and "CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET" in problem

    def test_a_short_secret_outside_dev_is_a_problem(self, monkeypatch):
        """@verifies REQ-0016"""
        monkeypatch.setenv("CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET", "x" * 31)
        assert "32" in KeycloakSettings().bootstrap_secret_problem()
        monkeypatch.setenv("CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET", "x" * 32)
        assert KeycloakSettings().bootstrap_secret_problem() is None

    def test_in_dev_it_is_optional(self, monkeypatch):
        """@verifies REQ-0016"""
        monkeypatch.setenv("ENV", "dev")
        settings = KeycloakSettings()
        assert settings.master_hardened is False
        assert settings.bootstrap_secret_problem() is None

    def test_in_dev_a_switch_turned_on_needs_it_too(self, monkeypatch):
        """Hardening runs only as the client, whatever the environment."""
        monkeypatch.setenv("ENV", "dev")
        monkeypatch.setenv("CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED", "true")
        assert KeycloakSettings().bootstrap_secret_problem()

    def test_an_empty_value_is_unset(self, monkeypatch):
        monkeypatch.setenv("CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET", "")
        assert KeycloakSettings().bootstrap_secret is None

    @pytest.mark.parametrize("extra", [[], ["--dry-run"], ["--check"]])
    def test_the_command_refuses_before_keycloak_is_asked_anything(self, monkeypatch, extra):
        """@verifies REQ-0016"""

        def no_keycloak(*args, **kwargs):
            raise AssertionError("Keycloak was asked")

        monkeypatch.setattr(bootstrap_module, "KeycloakAdminClient", no_keycloak)
        result = runner.invoke(app, [
            "keycloak", "bootstrap", str(PLATFORM_YAML), "-u", "http://kc",
            "--admin-user", "admin", "--admin-password", "admin", *extra,
        ])

        assert result.exit_code == 1
        assert "CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET" in result.output

    def test_the_secret_is_never_in_the_settings_repr(self, monkeypatch):
        monkeypatch.setenv("CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET", SECRET)
        assert SECRET not in repr(KeycloakSettings())


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------


class TestTheBootstrapClient:
    @pytest.mark.asyncio
    async def test_absent_it_is_created_with_the_configured_secret_and_its_roles(self):
        """@verifies REQ-0016"""
        master = MasterFake()
        await master.authenticate_admin_user()

        plan = await plan_client(master)
        await apply_bootstrap_client(master, plan, secret=SECRET)

        uuid = master.clients[CLIENT]["id"]
        assert master.secrets[uuid] == SECRET
        assert master.sa_roles[f"sa-{uuid}"]["realm"] == {"admin"}
        client = master.clients[CLIENT]
        assert client["serviceAccountsEnabled"] and not client["directAccessGrantsEnabled"]
        assert not client["standardFlowEnabled"] and not client["publicClient"]
        assert (await plan_client(master, as_client=True)).changes == []
        assert (await plan_client(master)).changes == []

    @pytest.mark.asyncio
    async def test_another_secret_and_flags_are_converged_by_the_admin_user(self):
        """@verifies REQ-0016"""
        master = MasterFake(client={
            "clientId": CLIENT, "enabled": True, "publicClient": False, "bearerOnly": False,
            "serviceAccountsEnabled": True, "standardFlowEnabled": True, "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": True, "clientAuthenticatorType": "client-secret",
            "_realm_roles": ["admin"],
        }, secret="rotated-away")
        await master.authenticate_admin_user()

        plan = await plan_client(master)
        keys = {c.key for c in plan.changes}
        assert keys == {f"client {CLIENT}.standardFlowEnabled", f"client {CLIENT}.directAccessGrantsEnabled",
                        f"client {CLIENT}.secret"}
        assert SECRET not in repr(plan.changes) and "rotated-away" not in repr(plan.changes)
        await apply_bootstrap_client(master, plan, secret=SECRET)

        assert master.secrets[f"uuid-{CLIENT}"] == SECRET
        assert master.clients[CLIENT]["directAccessGrantsEnabled"] is False
        assert (await plan_client(master)).changes == []

    @pytest.mark.asyncio
    async def test_a_missing_role_is_granted_and_reported(self):
        master = MasterFake(client={
            "clientId": CLIENT, "enabled": True, "publicClient": False, "bearerOnly": False,
            "serviceAccountsEnabled": True, "standardFlowEnabled": False, "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False, "clientAuthenticatorType": "client-secret",
            "_realm_roles": ["create-realm"],
        }, secret=SECRET)
        await master.authenticate_admin_user()

        plan = await plan_client(master)
        assert [c.key for c in plan.changes] == [f"client {CLIENT} realm roles"]
        await apply_bootstrap_client(master, plan, secret=SECRET)
        assert "admin" in master.sa_roles[f"sa-uuid-{CLIENT}"]["realm"]


# ---------------------------------------------------------------------------
# The guard: only the bootstrap client's own token hardens master
# ---------------------------------------------------------------------------


class TestOnlyTheBootstrapClientHardensMaster:
    @pytest.mark.parametrize("identity", [
        None,
        AuthIdentity(ADMIN_USER, "admin"),
        AuthIdentity(REALM_CLIENT, "celine-admin-cli"),
        AuthIdentity(MASTER_CLIENT, "some-other-client"),
    ])
    def test_any_other_session_is_refused(self, identity):
        """@verifies REQ-0016"""
        master = MasterFake()
        master.identity = identity
        with pytest.raises(MasterHardeningRefused):
            require_bootstrap_client(master, CLIENT)

    def test_the_bootstrap_client_is_accepted(self):
        master = MasterFake()
        master.identity = AuthIdentity(MASTER_CLIENT, CLIENT)
        require_bootstrap_client(master, CLIENT)

    @pytest.mark.asyncio
    async def test_an_admin_user_session_cannot_reach_the_hardening(self):
        """The plan is readable by anyone; the writes refuse before the first one.

        @verifies REQ-0016
        """
        master = MasterFake()
        await master.authenticate_admin_user()
        plan = await plan_master_hardening(master, declaration(), brute_force=True, mfa=True)
        assert plan.changes

        with pytest.raises(MasterHardeningRefused):
            await apply_master_hardening(master, plan, client_id=CLIENT)

        assert master.writes == []
        assert master.realm.get("bruteForceProtected") is False
        assert master.realm["browserFlow"] == "browser"

    @pytest.mark.asyncio
    async def test_the_real_client_records_who_signed_in(self):
        """`identity` is set by the sign-in methods, and only by them."""
        settings = KeycloakSettings(base_url="http://kc.invalid", admin_user="a", admin_password="b")
        kc = KeycloakAdminClient(settings.for_realm("master"))
        assert kc.identity is None
        other = KeycloakAdminClient(settings)
        other.identity = AuthIdentity(MASTER_CLIENT, CLIENT)
        kc.adopt_session(other)
        assert kc.identity == AuthIdentity(MASTER_CLIENT, CLIENT)


# ---------------------------------------------------------------------------
# The hardening
# ---------------------------------------------------------------------------


async def harden(master: MasterFake, *, brute_force=True, mfa=True):
    master.identity = AuthIdentity(MASTER_CLIENT, CLIENT)
    plan = await plan_master_hardening(master, declaration(), brute_force=brute_force, mfa=mfa)
    await apply_master_hardening(master, plan, client_id=CLIENT)
    again = await plan_master_hardening(master, declaration(), brute_force=brute_force, mfa=mfa)
    assert again.changes == [], again.changes
    return plan


class TestHardening:
    @pytest.mark.asyncio
    async def test_brute_force_takes_the_platform_tuning(self):
        """@verifies REQ-0016"""
        master = MasterFake()

        await harden(master)

        assert master.realm["bruteForceProtected"] is True
        for key, value in TUNING.items():
            assert master.realm[key] == value, key

    @pytest.mark.asyncio
    async def test_an_override_of_the_tuning_reaches_master_too(self):
        master = MasterFake()
        decl = declaration()
        decl.realm_settings["failureFactor"] = 3
        master.identity = AuthIdentity(MASTER_CLIENT, CLIENT)
        plan = await plan_master_hardening(master, decl, brute_force=True, mfa=False)
        assert {c.key: c.desired for c in plan.settings}["failureFactor"] == 3

    @pytest.mark.asyncio
    async def test_the_second_factor_flow_is_bound_on_masters_admin_role(self):
        """@verifies REQ-0016"""
        master = MasterFake()

        await harden(master)

        assert master.realm["browserFlow"] == ADMIN_MFA_FLOW
        expected = [(s.level, s.name, s.requirement) for s, _ in flatten(desired_flow("admin", organization=False))]
        assert master.flow_shape(ADMIN_MFA_FLOW) == expected
        assert master.config_of(ADMIN_MFA_FLOW, "conditional-user-role")["condUserRole"] == "admin"

    @pytest.mark.asyncio
    async def test_every_admin_without_a_one_time_code_must_enrol_one(self):
        """@verifies REQ-0016"""
        master = MasterFake(admins={
            "admin": {},
            "second-admin": {"credentials": ["password", "otp"]},
            "pending": {"requiredActions": [CONFIGURE_TOTP]},
            "service-account-x": {"service": True},
        })

        plan = await harden(master)

        assert [name for _, name in plan.enrol] == ["admin"]
        assert master.users["admin"]["requiredActions"] == [CONFIGURE_TOTP]
        assert master.users["second-admin"]["requiredActions"] == []
        assert master.users["service-account-x"]["requiredActions"] == []

    @pytest.mark.asyncio
    async def test_from_a_hardened_master_with_the_flow_on_the_old_shape(self):
        """Keycloak's own browser bound, brute force tuned otherwise: converged, then nothing."""
        master = MasterFake(realm={"bruteForceProtected": True, "failureFactor": 30, "browserFlow": "browser"})

        plan = await harden(master)

        assert {c.key for c in plan.settings} >= {"failureFactor"}
        assert not plan.destructive

    @pytest.mark.asyncio
    async def test_turning_it_off_is_destructive(self):
        """@verifies REQ-0016"""
        master = MasterFake()
        await harden(master)
        master.identity = AuthIdentity(MASTER_CLIENT, CLIENT)

        off = await plan_master_hardening(master, declaration(), brute_force=False, mfa=False)

        assert {c.key for c in off.destructive} == {"bruteForceProtected", "browserFlow"}
        assert all(destructive(c) for c in off.destructive)


# ---------------------------------------------------------------------------
# The whole run
# ---------------------------------------------------------------------------


def run_settings(**kwargs) -> KeycloakSettings:
    defaults = dict(base_url="http://kc.internal", realm="celine", admin_user="admin",
                    admin_password="admin", bootstrap_client_secret=SECRET)
    defaults.update(kwargs)
    return KeycloakSettings(**defaults)


async def run(settings, master, target, monkeypatch, **kwargs):
    monkeypatch.setattr(
        bootstrap_module, "KeycloakAdminClient",
        lambda s: master if s.realm == "master" else target,
    )
    args = dict(declaration=declaration(), client_id="celine-admin-cli", manage_admin_client=True,
                dry_run=False, admin_mfa=settings.admin_mfa, harden_master=settings.master_hardened)
    args.update(kwargs)
    return await bootstrap_module._async_bootstrap(settings=settings, **args)


def target_realm() -> JobRealm:
    realm = converged()
    realm["bruteForceProtected"] = True
    return JobRealm(realm, roles={"platform-admin"})


class TestTheRun:
    @pytest.mark.asyncio
    async def test_first_run_admin_user_creates_the_client_then_only_the_client_writes(self, monkeypatch):
        """(i) admin user because the client is absent, (ii) the client, (iii) its token,
        (iv) hardening with it.

        @verifies REQ-0016
        """
        master, target = MasterFake(), target_realm()

        result, _ = await run(run_settings(), master, target, monkeypatch)

        by_admin = [w for w in master.writes if w[-1] == AuthIdentity(ADMIN_USER, "admin")]
        assert by_admin and {w[0] for w in by_admin} <= {"create-client", "grant"}
        hardening = [w for w in master.writes if w[0] in {"master-realm", "put-user"}]
        assert hardening and all(w[-1] == AuthIdentity(MASTER_CLIENT, CLIENT) for w in hardening)
        assert master.identity == AuthIdentity(MASTER_CLIENT, CLIENT)
        assert master.realm["bruteForceProtected"] is True
        assert master.realm["browserFlow"] == ADMIN_MFA_FLOW
        assert master.users["admin"]["requiredActions"] == [CONFIGURE_TOTP]
        # the client's own service account holds `admin` too, and is never asked
        assert [w[1] for w in master.writes if w[0] == "put-user"] == ["admin"]
        assert target.realm["browserFlow"] == ADMIN_MFA_FLOW
        assert result.master_session == f"bootstrap client {CLIENT}"
        assert result.master_client and result.master and result.admin_mfa

    @pytest.mark.asyncio
    async def test_the_next_run_signs_in_as_the_client_and_changes_nothing(self, monkeypatch):
        """After the second factor the admin's password grant fails: the client is first.

        @verifies REQ-0016
        """
        master, target = MasterFake(), target_realm()
        await run(run_settings(), master, target, monkeypatch)

        async def no_password(*_):
            raise KeycloakAuthError("Account is not fully set up", status_code=400)

        master.authenticate_admin_user = no_password
        result, _ = await run(run_settings(), master, target, monkeypatch, dry_run=True)

        assert result.master_session == f"bootstrap client {CLIENT}"
        assert not result.master_client and not result.master and not result.admin_mfa

    @pytest.mark.asyncio
    async def test_if_the_switch_to_the_client_fails_nothing_is_hardened(self, monkeypatch):
        """@verifies REQ-0016"""
        master, target = MasterFake(), target_realm()
        original = master.authenticate_master_client
        calls = []

        async def refuse_after_creation(client_id, secret):
            calls.append(client_id)
            if len(calls) > 1:
                raise KeycloakAuthError("invalid_client", status_code=401)
            await original(client_id, secret)

        master.authenticate_master_client = refuse_after_creation

        with pytest.raises(KeycloakAuthError):
            await run(run_settings(), master, target, monkeypatch)

        assert not any(w[0] in {"master-realm", "put-user", "flow"} for w in master.writes)
        assert master.realm["bruteForceProtected"] is False

    @pytest.mark.asyncio
    async def test_a_session_left_on_the_admin_user_cannot_reach_the_hardening(self, monkeypatch):
        """Even if the switch were skipped, the admin user's token never hardens master.

        @verifies REQ-0016
        """
        master, target = MasterFake(), target_realm()

        async def stay_admin(client_id, secret):
            if client_id in master.clients:
                return  # pretends to switch, leaves the admin user's identity
            raise KeycloakAuthError("invalid_client", status_code=401)

        master.authenticate_master_client = stay_admin

        with pytest.raises(MasterHardeningRefused):
            await run(run_settings(), master, target, monkeypatch)

        assert master.realm["bruteForceProtected"] is False
        assert master.realm["browserFlow"] == "browser"
        assert master.users["admin"]["requiredActions"] == []

    @pytest.mark.asyncio
    async def test_dev_leaves_master_alone_and_the_realm_without_the_second_factor(self, monkeypatch):
        """@verifies REQ-0016"""
        master, target = MasterFake(), JobRealm(converged(), roles={"platform-admin"})
        settings = run_settings(env="dev", bootstrap_client_secret=None)

        result, _ = await run(settings, master, target, monkeypatch)

        assert master.writes == []
        assert master.realm == {"bruteForceProtected": False, "browserFlow": "browser"}
        assert target.realm["browserFlow"] == "browser"
        assert target.realm["bruteForceProtected"] is False
        assert result.master_session == "master admin user admin"
        assert result.master_skipped

    @pytest.mark.asyncio
    async def test_dev_with_the_secret_manages_the_client_and_hardens_nothing(self, monkeypatch):
        master, target = MasterFake(), JobRealm(converged(), roles={"platform-admin"})

        await run(run_settings(env="dev"), master, target, monkeypatch)

        assert CLIENT in master.clients
        assert not any(w[0] in {"master-realm", "put-user"} for w in master.writes)


# ---------------------------------------------------------------------------
# Every other command signs in as the bootstrap client when the admin user cannot
# ---------------------------------------------------------------------------


def jwt(claims: dict) -> str:
    import base64
    import json

    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"e30.{body}.sig"


def token_endpoint(*, client_ok: bool = True, azp: str = CLIENT, admin_ok: bool = True):
    import httpx

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
        seen.append(f"{request.url.path} {form['grant_type']}")
        if form["grant_type"] == "client_credentials":
            if not client_ok:
                return httpx.Response(401, json={"error": "invalid_client"})
            token = jwt({"azp": azp, "iss": "http://kc.internal/realms/master"})
        else:
            if not admin_ok:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "Account is not fully set up"})
            token = jwt({"azp": "admin-cli", "iss": "http://kc.internal/realms/master"})
        return httpx.Response(200, json={"access_token": token, "expires_in": 300})

    return httpx.MockTransport(handler), seen


async def sign_in(transport, **settings_kwargs) -> KeycloakAdminClient:
    import httpx

    settings = KeycloakSettings(base_url="http://kc.internal", **settings_kwargs)
    kc = KeycloakAdminClient(settings)
    kc._client = httpx.AsyncClient(transport=transport)
    await kc.authenticate()
    return kc


class TestOtherCommandsSignIn:
    @pytest.mark.asyncio
    async def test_with_the_secret_they_sign_in_as_the_bootstrap_client(self):
        """`sync` in a deployment: the admin's password no longer works after hardening.

        @verifies REQ-0016
        """
        transport, seen = token_endpoint(admin_ok=False)
        kc = await sign_in(transport, admin_user="admin", admin_password="admin",
                           bootstrap_client_secret=SECRET)
        assert kc.identity == AuthIdentity(MASTER_CLIENT, CLIENT)
        assert seen == ["/realms/master/protocol/openid-connect/token client_credentials"]

    @pytest.mark.asyncio
    async def test_a_failing_client_falls_back_to_the_admin_user(self):
        transport, seen = token_endpoint(client_ok=False)
        kc = await sign_in(transport, admin_user="admin", admin_password="admin",
                           bootstrap_client_secret=SECRET)
        assert kc.identity == AuthIdentity(ADMIN_USER, "admin")

    @pytest.mark.asyncio
    async def test_a_token_that_is_not_the_clients_own_is_refused(self):
        """@verifies REQ-0016"""
        transport, _ = token_endpoint(azp="someone-else")
        with pytest.raises(KeycloakAuthError, match="not that client's own"):
            await sign_in(transport, bootstrap_client_secret=SECRET)

    @pytest.mark.asyncio
    async def test_the_admin_cli_client_still_comes_first(self):
        transport, seen = token_endpoint()
        kc = await sign_in(transport, admin_client_secret="cli-secret", bootstrap_client_secret=SECRET)
        assert kc.identity == AuthIdentity(REALM_CLIENT, "celine-admin-cli")
        assert seen == ["/realms/celine/protocol/openid-connect/token client_credentials"]
