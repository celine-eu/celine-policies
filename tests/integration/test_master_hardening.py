"""The admin second factor and the master realm against a real Keycloak (REQ-0015, REQ-0016).

**Changes the master realm**, which is global to a Keycloak instance, so it runs only against a
throwaway one named on purpose:

    CELINE_MASTER_HARDENING_KEYCLOAK_URL   a throwaway Keycloak 26.7.3 with the `rec` theme
                                           (the celine-policies image), master admin
                                           `admin`/`admin`, and no realm `celine`

It refuses a Keycloak that has a realm `celine`: that is a shared development Keycloak, whose
master must never be hardened by a test. It creates the realm `master-hardening-test` and the
master client `svc-celine-policies-bootstrap`, and puts master back as it found it at the end
(brute force off, Keycloak's own browser flow, no required action on `admin`) using the
bootstrap client, since by then the admin's password alone no longer signs in.

What it shows, outside dev (ENV=prod):

1. from old states (the platform realm with infra's import flow bound and conditioned on the
   retired role `admin`; master with brute force tuned otherwise and the client holding
   another secret, direct grants on and no role), one `bootstrap` run converges the
   platform realm's flow, master's brute force and master's second factor;
2. the master admin's password grant then fails, and the next run still works, as the client,
   and `--check` finds nothing;
3. through a real browser sign-in (authorization code, the login form posted as a browser
   would): a platform admin and the master admin are asked for a second factor (made to enrol
   TOTP), an organization admin is not;
4. in dev, nothing is enabled on either realm.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import json
import os
import re
import secrets
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from celine.policies.cli.keycloak.admin_mfa import ADMIN_MFA_FLOW, _build, desired_flow
from celine.policies.cli.keycloak.client import KeycloakAdminClient
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.policies.cli.main import app

BASE = os.environ.get("CELINE_MASTER_HARDENING_KEYCLOAK_URL")
REALM = "master-hardening-test"
CLIENT = "svc-celine-policies-bootstrap"
SECRET = "it-" + "0123456789abcdef" * 3
REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    not BASE, reason="needs a throwaway Keycloak: CELINE_MASTER_HARDENING_KEYCLOAK_URL"
)

runner = CliRunner()

CLIENTS = f"""\
realm: {REALM}
oauth2_proxy_client: web
scopes: []
clients:
  - client_id: web
    name: web
    secret: web-test-secret-0123456789abcdef
    service_account_enabled: false
    default_scopes: [web-origins, acr, profile, roles, email]
    browser:
      redirect_uris: ["https://web.example.org/*"]
"""


def ok(response: httpx.Response) -> httpx.Response:
    assert response.status_code < 300, f"{response.request.method} {response.request.url}: {response.status_code} {response.text}"
    return response


def admin_password_grant() -> httpx.Response:
    return httpx.post(
        f"{BASE}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
        timeout=30,
    )


def client_token() -> str:
    return ok(httpx.post(
        f"{BASE}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "client_credentials", "client_id": CLIENT, "client_secret": SECRET},
        timeout=30,
    )).json()["access_token"]


def admin_api(token: str, realm: str) -> httpx.Client:
    return httpx.Client(base_url=f"{BASE}/admin/realms/{realm}",
                        headers={"Authorization": f"Bearer {token}"}, timeout=60)


def make_user(kc: httpx.Client, username: str) -> str:
    ok(kc.post("/users", json={
        "username": username, "enabled": True, "email": f"{username}@example.org", "emailVerified": True,
        "firstName": "Test", "lastName": username,
        "credentials": [{"type": "password", "value": username, "temporary": False}],
    }))
    return kc.get("/users", params={"username": username, "exact": "true"}).json()[0]["id"]


def run_bootstrap(tmp_path: Path, *extra: str, admin: bool = True):
    args = ["keycloak", "bootstrap", str(REPO_ROOT / "platform.yaml"), "-u", BASE, "-r", REALM,
            "--secrets-file", str(tmp_path / "secrets.yaml"), *extra]
    if admin:
        args += ["--admin-user", "admin", "--admin-password", "admin"]
    return runner.invoke(app, args)


def executions(kc: httpx.Client, alias: str) -> list[tuple[int, str, str]]:
    return [
        (e["level"], e["displayName"] if e.get("authenticationFlow") else e["providerId"], e["requirement"])
        for e in ok(kc.get(f"/authentication/flows/{alias}/executions")).json()
    ]


def role_condition(kc: httpx.Client, alias: str) -> str:
    for e in ok(kc.get(f"/authentication/flows/{alias}/executions")).json():
        if e.get("providerId") == "conditional-user-role":
            return ok(kc.get(f"/authentication/config/{e['authenticationConfig']}")).json()["config"]["condUserRole"]
    raise AssertionError("no role condition")


class Browser:
    """Just enough of a browser: follows redirects and keeps cookies by hand. Keycloak marks
    its cookies `Secure`, which httpx then never sends back over plain http."""

    def __init__(self):
        self.http = httpx.Client(timeout=30, follow_redirects=False)
        self.cookies: dict[str, str] = {}

    def send(self, method: str, url: str, **kwargs) -> httpx.Response:
        for _ in range(10):
            headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())}
            response = self.http.request(method, url, headers=headers, **kwargs)
            for raw in response.headers.get_list("set-cookie"):
                name, _, rest = raw.partition("=")
                value = rest.split(";", 1)[0]
                if value:
                    self.cookies[name.strip()] = value
                else:
                    self.cookies.pop(name.strip(), None)
            if response.status_code not in (301, 302, 303) or "code=" in response.headers.get("location", ""):
                return response
            method, url, kwargs = "GET", str(response.url.join(response.headers["location"])), {}
        raise AssertionError("too many redirects")


def browser_sign_in(realm: str, client_id: str, redirect_uri: str, username: str, password: str) -> str:
    """Sign in as a browser does: authorization endpoint, the login form posted with its cookies.

    Returns "signed-in" (redirected back with a code), "enrol-totp" (Keycloak's TOTP setup
    page) or "otp" (the one-time code form); anything else fails with the page's message.
    """
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    browser = Browser()
    answer = ok(browser.send("GET", f"{BASE}/realms/{realm}/protocol/openid-connect/auth", params={
        "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
        "scope": "openid", "state": "s", "code_challenge": challenge, "code_challenge_method": "S256",
    }))
    for _ in range(3):  # the username and password pages, if Keycloak splits them
        action = re.search(r'<form[^>]*action="([^"]*login-actions/authenticate[^"]*)"', answer.text)
        if action is None or not re.search(r'name="(username|password)"', answer.text):
            break
        answer = browser.send("POST", html.unescape(action.group(1)),
                              data={"username": username, "password": password})
        location = answer.headers.get("location", "")
        if answer.status_code in (302, 303) and location.startswith(redirect_uri.rstrip("/")) and "code=" in location:
            return "signed-in"
    body = answer.text
    if 'name="totpSecret"' in body or 'id="kc-totp-secret-key"' in body:
        return "enrol-totp"
    if 'name="otp"' in body:
        return "otp"
    shown = re.findall(r'(?:kc-feedback-text|kc-page-title|instruction)[^>]*>\s*([^<]+)', body)
    raise AssertionError(f"{username}: unexpected page {answer.status_code} {answer.url}: {shown}")


def build_old_import_flow(realm: str, token: str) -> None:
    """Infra's import flow, conditioned on the retired role `admin`, built through the API."""

    async def build():
        settings = KeycloakSettings(base_url=BASE, realm=realm, admin_user="admin", admin_password="admin")
        async with KeycloakAdminClient(settings) as kc:
            await kc.authenticate_admin_user()
            await kc.create_top_level_flow(ADMIN_MFA_FLOW, "infra's realm import")
            await _build(kc, ADMIN_MFA_FLOW, desired_flow("admin"))
            await kc.update_realm_settings({"browserFlow": ADMIN_MFA_FLOW})

    asyncio.run(build())


def restore_master() -> None:
    """Master as Keycloak makes it, through the bootstrap client: the admin is MFA-bound."""
    try:
        token = client_token()
    except AssertionError:
        token = ok(admin_password_grant()).json()["access_token"]
    master = admin_api(token, "master")
    ok(master.put("", json={"bruteForceProtected": False, "browserFlow": "browser"}))
    for flow in master.get("/authentication/flows").json():
        if flow["alias"] == ADMIN_MFA_FLOW:
            ok(master.delete(f"/authentication/flows/{flow['id']}"))
    for user in master.get("/roles/admin/users").json():
        rep = ok(master.get(f"/users/{user['id']}")).json()
        if rep.get("requiredActions"):
            ok(master.put(f"/users/{user['id']}", json={**rep, "requiredActions": []}))
    admin = admin_api(ok(admin_password_grant()).json()["access_token"], "master")
    if httpx.get(f"{BASE}/admin/realms/{REALM}", headers=admin.headers, timeout=60).status_code == 200:
        ok(httpx.delete(f"{BASE}/admin/realms/{REALM}", headers=admin.headers, timeout=60))
    for client in admin.get("/clients", params={"clientId": CLIENT}).json():
        ok(admin.delete(f"/clients/{client['id']}"))


@pytest.fixture
def keycloak(monkeypatch):
    token = ok(admin_password_grant()).json()["access_token"]
    realms = [r["realm"] for r in ok(httpx.get(f"{BASE}/admin/realms", headers={"Authorization": f"Bearer {token}"})).json()]
    if "celine" in realms:
        pytest.fail(f"{BASE} has a realm 'celine': a shared Keycloak, whose master this test must not harden")
    restore_master()
    for key in list(os.environ):
        if key.startswith("CELINE_KEYCLOAK_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET", SECRET)
    monkeypatch.setenv("CELINE_KEYCLOAK_REALM_ADMIN_USERNAME", "ops-admin")
    monkeypatch.setenv("CELINE_KEYCLOAK_REALM_ADMIN_EMAIL", "ops-admin@example.org")
    monkeypatch.setenv("CELINE_KEYCLOAK_REALM_ADMIN_PASSWORD", "ops-admin")
    yield
    restore_master()


def seed_old_states() -> None:
    admin = admin_api(ok(admin_password_grant()).json()["access_token"], "master")
    # The platform realm: the import's flow, on the retired role, bound; the role itself.
    ok(httpx.post(f"{BASE}/admin/realms", headers=admin.headers, json={"realm": REALM, "enabled": True}))
    target = admin_api(admin.headers["Authorization"].split()[1], REALM)
    ok(target.post("/roles", json={"name": "admin"}))
    build_old_import_flow(REALM, "")
    # Master: brute force tuned otherwise; the client with another secret, direct grants on,
    # and no role.
    ok(admin.put("", json={"bruteForceProtected": True, "failureFactor": 30}))
    ok(admin.post("/clients", json={
        "clientId": CLIENT, "publicClient": False, "serviceAccountsEnabled": True,
        "directAccessGrantsEnabled": True, "standardFlowEnabled": False, "secret": "another-secret",
    }))


@pytest.mark.usefixtures("keycloak")
class TestOutsideDev:
    def test_from_old_states_it_converges_and_the_next_run_is_the_clients(self, tmp_path, monkeypatch):
        """@verifies REQ-0015
        @verifies REQ-0016
        """
        monkeypatch.setenv("ENV", "prod")
        seed_old_states()

        first = run_bootstrap(tmp_path, "--allow-destructive")
        assert first.exit_code == 0, first.output
        assert "signed in as bootstrap client" in first.output

        # The admin's password grant now fails: CONFIGURE_TOTP is pending.
        refused = admin_password_grant()
        assert refused.status_code == 400 and "not fully set up" in refused.text, refused.text

        token = client_token()
        master = admin_api(token, "master")
        rep = ok(master.get("")).json()
        assert rep["bruteForceProtected"] is True
        assert (rep["permanentLockout"], rep["failureFactor"], rep["waitIncrementSeconds"],
                rep["maxFailureWaitSeconds"]) == (False, 5, 60, 900)
        assert rep["browserFlow"] == ADMIN_MFA_FLOW
        assert role_condition(master, ADMIN_MFA_FLOW) == "admin"
        assert not any("rganization" in name for _, name, _ in executions(master, ADMIN_MFA_FLOW))
        admin_user = master.get("/users", params={"username": "admin", "exact": "true"}).json()[0]
        assert "CONFIGURE_TOTP" in admin_user["requiredActions"]
        client = master.get("/clients", params={"clientId": CLIENT}).json()[0]
        assert client["directAccessGrantsEnabled"] is False and client["serviceAccountsEnabled"] is True
        sa = ok(master.get(f"/clients/{client['id']}/service-account-user")).json()
        realm_roles = {r["name"] for r in ok(master.get(f"/users/{sa['id']}/role-mappings/realm")).json()}
        assert "admin" in realm_roles
        assert ok(master.get(f"/users/{sa['id']}")).json().get("requiredActions") == []

        target = admin_api(token, REALM)
        assert ok(target.get("")).json()["browserFlow"] == ADMIN_MFA_FLOW
        assert role_condition(target, ADMIN_MFA_FLOW) == "platform-admin"
        assert target.get("/roles/admin").status_code == 404

        # The next run: no admin user can sign in any more; the client does it all.
        second = run_bootstrap(tmp_path, admin=False)
        assert second.exit_code == 0, second.output
        assert "signed in as bootstrap client" in second.output
        check = run_bootstrap(tmp_path, "--check", admin=False)
        assert check.exit_code == 0, check.output
        assert "Check passed" in check.output
        # And with the admin's (now failing) credentials given too, the client still comes first.
        third = run_bootstrap(tmp_path, "--check")
        assert third.exit_code == 0, third.output

        # `sync`, as a deployment's shell runs it with the admin user configured: it signs in
        # as the bootstrap client, since the admin's password alone no longer does.
        (tmp_path / "clients.yaml").write_text(CLIENTS)
        synced = runner.invoke(app, [
            "keycloak", "sync", str(tmp_path / "clients.yaml"), "-u", BASE, "-r", REALM,
            "--admin-user", "admin", "--admin-password", "admin",
            "--secrets-file", str(tmp_path / "secrets.yaml"),
        ])
        assert synced.exit_code == 0, synced.output
        assert ok(target.get("/clients", params={"clientId": "web"})).json()

    def test_a_platform_admin_and_the_master_admin_need_a_second_factor_an_org_admin_does_not(
        self, tmp_path, monkeypatch
    ):
        """Real browser sign-ins, after bootstrap, and bootstrap still runs afterwards.

        @verifies REQ-0015
        @verifies REQ-0016
        """
        monkeypatch.setenv("ENV", "prod")
        first = run_bootstrap(tmp_path)
        assert first.exit_code == 0, first.output

        target = admin_api(client_token(), REALM)
        org_admin = make_user(target, "org-admin")
        ok(target.post("/organizations", json={
            "name": "Example REC", "alias": "example-rec", "enabled": True,
            "domains": [{"name": "rec.example.org"}],
        }))
        org = next(o for o in target.get("/organizations").json() if o["alias"] == "example-rec")
        ok(target.post(f"/organizations/{org['id']}/members", content=json.dumps(org_admin),
                       headers={"Content-Type": "application/json"}))
        ok(target.post(f"/organizations/{org['id']}/groups", json={"name": "admins"}))
        group = next(g for g in target.get(f"/organizations/{org['id']}/groups").json() if g["name"] == "admins")
        ok(target.put(f"/organizations/{org['id']}/groups/{group['id']}/members/{org_admin}"))

        account = f"{BASE}/realms/{REALM}/account/"
        assert browser_sign_in(REALM, "account-console", account, "org-admin", "org-admin") == "signed-in"
        assert browser_sign_in(REALM, "account-console", account, "ops-admin", "ops-admin") == "enrol-totp"
        console = f"{BASE}/admin/master/console/"
        assert browser_sign_in("master", "security-admin-console", console, "admin", "admin") == "enrol-totp"

        again = run_bootstrap(tmp_path, "--check", admin=False)
        assert again.exit_code == 0, again.output


@pytest.mark.usefixtures("keycloak")
class TestDev:
    def test_nothing_is_enabled_on_either_realm(self, tmp_path, monkeypatch):
        """@verifies REQ-0015
        @verifies REQ-0016
        """
        monkeypatch.setenv("ENV", "dev")
        monkeypatch.delenv("CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET")

        result = run_bootstrap(tmp_path)
        assert result.exit_code == 0, result.output
        check = run_bootstrap(tmp_path, "--check")
        assert check.exit_code == 0, check.output

        token = ok(admin_password_grant()).json()["access_token"]
        master = ok(admin_api(token, "master").get("")).json()
        assert master["bruteForceProtected"] is False and master["browserFlow"] == "browser"
        target = admin_api(token, REALM)
        rep = ok(target.get("")).json()
        assert rep["bruteForceProtected"] is False and rep["browserFlow"] == "browser"
        assert browser_sign_in(REALM, "account-console", f"{BASE}/realms/{REALM}/account/",
                               "ops-admin", "ops-admin") == "signed-in"
        assert browser_sign_in("master", "security-admin-console", f"{BASE}/admin/master/console/",
                               "admin", "admin") == "signed-in"
