"""The two-level model against a real Keycloak, from the old state (REQ-0011 – REQ-0013).

Skipped unless a Keycloak is named:

    CELINE_SYNC_KEYCLOAK_URL   any Keycloak accepting the master admin `admin`/`admin`
                               (falls back to CELINE_PARITY_EMPTY_URL, which CI starts)

The Keycloak must ship the `rec` theme (the celine-policies image does), or bootstrap refuses
`platform.yaml`'s themes. It creates and deletes a realm of its own, `platform-admin-role-test`,
and touches nothing else.

The realm is first put in the state every deployed realm is in today, made by hand through the
Admin API: the four role groups with their realm roles, a user in `/admins`, a `groups` client
scope writing `/admins`, a client-level mapper writing `admins`, `microprofile-jwt` writing realm
roles into `groups`, and an organization whose own `admins` group has the path `/admins` too.
On top of that, the platform role handed out the wrong ways: mapped onto the organization's
group and put in the realm's default roles. Then `bootstrap` and `sync` run, twice; the realm
must be in the new state after the first run and unchanged by the second, and real tokens minted
by a direct grant must carry exactly the two levels.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from celine.policies.cli.main import app

BASE = os.environ.get("CELINE_SYNC_KEYCLOAK_URL") or os.environ.get("CELINE_PARITY_EMPTY_URL")
REALM = "platform-admin-role-test"
REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    not BASE, reason="needs a Keycloak: CELINE_SYNC_KEYCLOAK_URL (or CELINE_PARITY_EMPTY_URL)"
)

runner = CliRunner()

CLIENTS = f"""\
realm: {REALM}
oauth2_proxy_client: web
scopes: []
clients:
  - client_id: web
    name: web
    secret: web-test-secret
    service_account_enabled: false
    default_scopes: [web-origins, acr, profile, roles, email]
    browser:
      redirect_uris: ["http://web.example.org/*"]
      direct_access_grants: true
"""

LEGACY = {"/admins": "admin", "/managers": "manager", "/editors": "editor", "/viewers": "viewer"}


def master() -> httpx.Client:
    token = httpx.post(
        f"{BASE}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
        timeout=30,
    ).json()["access_token"]
    return httpx.Client(
        base_url=f"{BASE}/admin/realms/{REALM}", headers={"Authorization": f"Bearer {token}"}, timeout=60
    )


def ok(response: httpx.Response) -> httpx.Response:
    assert response.status_code < 300, f"{response.request.method} {response.request.url}: {response.status_code} {response.text}"
    return response


def make_user(kc: httpx.Client, username: str) -> str:
    ok(kc.post("/users", json={
        "username": username, "enabled": True, "email": f"{username}@example.org", "emailVerified": True,
        "firstName": "Test", "lastName": username,
        "credentials": [{"type": "password", "value": username, "temporary": False}],
    }))
    return kc.get("/users", params={"username": username, "exact": "true"}).json()[0]["id"]


def role(kc: httpx.Client, name: str) -> dict:
    return ok(kc.get(f"/roles/{name}")).json()


def seed_the_old_state(kc: httpx.Client) -> dict[str, str]:
    """Everything the old platform level and its mappers left in a realm."""
    ids: dict[str, str] = {}
    for path, name in LEGACY.items():
        ok(kc.post("/roles", json={"name": name}))
        ok(kc.post("/groups", json={"name": path[1:]}))
        gid = next(g["id"] for g in kc.get("/groups", params={"search": path[1:], "exact": "true"}).json())
        ok(kc.post(f"/groups/{gid}/role-mappings/realm", json=[role(kc, name)]))
        ids[path] = gid
    ids["legacy-admin"] = make_user(kc, "legacy-admin")
    ok(kc.put(f"/users/{ids['legacy-admin']}/groups/{ids['/admins']}"))
    ids["org-admin"] = make_user(kc, "org-admin")

    # The organization, its own `admins` group (path `/admins` too) and a member of it.
    ok(kc.post("/organizations", json={
        "name": "Example Org", "alias": "example-org", "enabled": True,
        "domains": [{"name": "example-org.example.org"}],
    }))
    org = next(o for o in kc.get("/organizations").json() if o["alias"] == "example-org")
    ids["org"] = org["id"]
    ok(kc.post(f"/organizations/{org['id']}/groups", json={"name": "admins"}))
    ids["org-group"] = next(g["id"] for g in kc.get(f"/organizations/{org['id']}/groups").json())
    ok(kc.post(f"/organizations/{org['id']}/members", content=json.dumps(ids["org-admin"]),
               headers={"Content-Type": "application/json"}))
    ok(kc.put(f"/organizations/{org['id']}/groups/{ids['org-group']}/members/{ids['org-admin']}"))

    # The platform role handed out the wrong ways: to a whole organization group, and to
    # every user through the realm's default roles.
    ok(kc.post("/roles", json={"name": "platform-admin"}))
    # Only the Organization API maps a role onto an organization group (`/groups/{id}` answers
    # 400 for one), and on 26.7.3 the mapping reaches no member's token: asserted below.
    ok(kc.post(f"/organizations/{org['id']}/groups/{ids['org-group']}/role-mappings/realm",
               json=[role(kc, "platform-admin")]))
    default_role = ok(kc.get("")).json()["defaultRole"]
    ok(kc.post(f"/roles-by-id/{default_role['id']}/composites", json=[role(kc, "platform-admin")]))
    return ids


def seed_the_old_mappers(kc: httpx.Client) -> None:
    """Both `groups` mappers the local realm had, on the client and a scope; microprofile-jwt."""
    ok(kc.post("/client-scopes", json={"name": "groups", "protocol": "openid-connect"}))
    sid = next(s["id"] for s in kc.get("/client-scopes").json() if s["name"] == "groups")
    ok(kc.post(f"/client-scopes/{sid}/protocol-mappers/models", json={
        "name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
        "config": {"claim.name": "groups", "full.path": "true", "access.token.claim": "true",
                   "id.token.claim": "true", "userinfo.token.claim": "true"},
    }))
    web = kc.get("/clients", params={"clientId": "web"}).json()[0]["id"]
    ok(kc.put(f"/clients/{web}/default-client-scopes/{sid}"))
    ok(kc.post(f"/clients/{web}/protocol-mappers/models", json={
        "name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
        "config": {"claim.name": "groups", "full.path": "false", "access.token.claim": "true",
                   "id.token.claim": "true", "userinfo.token.claim": "true"},
    }))
    mp = next(s for s in kc.get("/client-scopes").json() if s["name"] == "microprofile-jwt")
    if not any(m.get("config", {}).get("claim.name") == "groups"
               for m in kc.get(f"/client-scopes/{mp['id']}/protocol-mappers/models").json()):
        ok(kc.post(f"/client-scopes/{mp['id']}/protocol-mappers/models", json={
            "name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "config": {"claim.name": "groups", "multivalued": "true", "access.token.claim": "true"},
        }))
    ok(kc.put(f"/clients/{web}/optional-client-scopes/{mp['id']}"))


def bootstrap(tmp_path: Path, *extra: str):
    return runner.invoke(app, [
        "keycloak", "bootstrap", str(REPO_ROOT / "platform.yaml"), "--overlay", str(tmp_path / "overlay.yaml"),
        "-u", BASE, "-r", REALM, "--admin-user", "admin", "--admin-password", "admin",
        "--secrets-file", str(tmp_path / "secrets.yaml"), *extra,
    ])


def sync(tmp_path: Path):
    return runner.invoke(app, [
        "keycloak", "sync", str(tmp_path / "clients.yaml"), "-u", BASE, "-r", REALM,
        "--admin-user", "admin", "--admin-password", "admin", "--secrets-file", str(tmp_path / "secrets.yaml"),
    ])


def claims_of(username: str, scope: str = "openid organization:*") -> dict:
    response = ok(httpx.post(
        f"{BASE}/realms/{REALM}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "web", "client_secret": "web-test-secret",
              "username": username, "password": username, "scope": scope},
        timeout=30,
    ))
    payload = response.json()["access_token"].split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def groups_claim_writers(kc: httpx.Client) -> list[str]:
    found = []
    for scope in kc.get("/client-scopes").json():
        for m in kc.get(f"/client-scopes/{scope['id']}/protocol-mappers/models").json():
            if m.get("config", {}).get("claim.name") == "groups" or m["protocolMapper"] == "oidc-group-membership-mapper":
                found.append(f"{scope['name']}/{m['name']}")
    for client in kc.get("/clients").json():
        for m in client.get("protocolMappers") or []:
            if m.get("config", {}).get("claim.name") == "groups" or m["protocolMapper"] == "oidc-group-membership-mapper":
                found.append(f"{client['clientId']}/{m['name']}")
    return found


@pytest.fixture
def realm(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ENV", "dev")
    (tmp_path / "clients.yaml").write_text(CLIENTS)
    (tmp_path / "overlay.yaml").write_text(
        "platform_admin:\n  users: [legacy-admin, not-created-yet]\n"
    )
    root = httpx.Client(
        base_url=f"{BASE}/admin/realms", headers=master().headers, timeout=60
    )
    root.delete(f"/{REALM}")
    ok(root.post("", json={"realm": REALM, "enabled": True, "organizationsEnabled": True}))
    yield master()
    master().delete("")


def test_bootstrap_and_sync_converge_an_old_realm_to_two_levels(realm, tmp_path):
    """@verifies REQ-0011
    @verifies REQ-0012
    @verifies REQ-0013
    """
    kc = realm
    # `sync` creates the browser client first, on the old realm, so its old mappers can be added.
    first_sync = sync(tmp_path)
    assert first_sync.exit_code == 0, first_sync.output
    ids = seed_the_old_state(kc)
    seed_the_old_mappers(kc)
    assert groups_claim_writers(kc), "the old mappers were not seeded"
    old = claims_of("legacy-admin", scope="openid")
    assert "/admins" in old["groups"] and "admins" in old["groups"]

    applied = bootstrap(tmp_path)
    assert applied.exit_code == 0, applied.output
    assert "  - realm group /admins (retired)" in applied.output
    assert "  - platform-admin inside composite role default-roles-platform-admin-role-test" in applied.output
    assert "  + legacy-admin -> realm role platform-admin" in applied.output
    assert "not-created-yet: listed in platform_admin.users but not in the realm yet" in applied.output
    synced = sync(tmp_path)
    assert synced.exit_code == 0, synced.output
    assert "groups claim: client web: mapper groups (oidc-group-membership-mapper) (removed)" in synced.output

    # The realm: no retired group or role, the role held directly by the declared user only.
    assert [g["path"] for g in kc.get("/groups").json()] == []
    roles = {r["name"] for r in kc.get("/roles").json()}
    assert "platform-admin" in roles and not roles & set(LEGACY.values())
    assert [u["username"] for u in kc.get("/roles/platform-admin/users").json()] == ["legacy-admin"]
    assert kc.get("/roles/platform-admin/groups").json() == []
    default_role = kc.get("").json()["defaultRole"]
    composites = {r["name"] for r in kc.get(f"/roles-by-id/{default_role['id']}/composites/realm").json()}
    assert "platform-admin" not in composites
    # The organization's own group survived, member and all.
    org_groups = kc.get(f"/organizations/{ids['org']}/groups").json()
    assert [g["name"] for g in org_groups] == ["admins"]
    member_groups = kc.get(f"/organizations/{ids['org']}/members/{ids['org-admin']}/groups").json()
    assert [g["id"] for g in member_groups] == [ids["org-group"]]
    # No mapper writes `groups`, and no `groups` scope.
    assert groups_claim_writers(kc) == []
    assert "groups" not in {s["name"] for s in kc.get("/client-scopes").json()}

    # Real tokens.
    admin = claims_of("legacy-admin")
    assert "platform-admin" in admin["realm_access"]["roles"]
    assert not set(admin["realm_access"]["roles"]) & set(LEGACY.values())
    assert "groups" not in admin
    org_admin = claims_of("org-admin")
    assert "platform-admin" not in org_admin.get("realm_access", {}).get("roles", [])
    assert org_admin["organization"]["example-org"]["groups"] == ["/admins"]
    assert "groups" not in org_admin
    # microprofile-jwt requested explicitly writes no `groups` either.
    assert "groups" not in claims_of("legacy-admin", scope="openid microprofile-jwt")

    # A second run changes nothing.
    check = bootstrap(tmp_path, "--check")
    assert check.exit_code == 0, check.output
    again = sync(tmp_path)
    assert again.exit_code == 0, again.output
    assert "groups claim" not in again.output
