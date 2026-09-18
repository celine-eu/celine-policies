"""Parity: a realm built by `bootstrap` alone equals one built from the import, at platform level.

Decision 1 of plan each-cli-command-owns-one-level: `bootstrap` creates the realm and the
realm import is dropped, **but only once parity is proven**. This is that proof, and it
runs against two real Keycloaks, so it is skipped unless both are named:

    CELINE_PARITY_IMPORTED_URL   a Keycloak started with --import-realm (realm `celine` exists)
    CELINE_PARITY_EMPTY_URL      a Keycloak with no `celine` realm

Both must accept the master admin `admin`/`admin` and ship the `rec` themes (this
repository's `keycloak` image). `.github/workflows/test.yaml` starts them.

Realm A is the import converged by `bootstrap`. Realm B is created and converged by
`bootstrap`. Every platform-level value is compared: each key `platform.yaml` declares,
`bruteForceProtected`, and the role groups with their realm roles, read from a partial
export as the master admin. A second `bootstrap --check` on each must find nothing.

One client is compared: the built-in `account-console`, whose default client scopes
`bootstrap` converges (an imported realm has none, and the account console answers 403).
Both realms must end with Keycloak's own set, and its token must carry the `account` roles.

What this does not compare, on purpose: other clients, client scopes and users. They are not
platform level, and the import carries some of them (`oauth2_proxy`, the realm admin
user) that nothing else declares yet — which is why passing here is necessary for dropping
the import and not sufficient.

Once the import is dropped, the test stays and compares realm B against a committed
reference export instead, so parity cannot silently regress.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from celine.policies.cli.keycloak.platform import ACCOUNT_CONSOLE_DEFAULT_SCOPES
from celine.policies.cli.main import app

REPO_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_YAML = REPO_ROOT / "platform.yaml"
REALM = "celine"

IMPORTED = os.environ.get("CELINE_PARITY_IMPORTED_URL")
EMPTY = os.environ.get("CELINE_PARITY_EMPTY_URL")

pytestmark = pytest.mark.skipif(
    not (IMPORTED and EMPTY),
    reason="needs two Keycloaks: CELINE_PARITY_IMPORTED_URL and CELINE_PARITY_EMPTY_URL",
)

runner = CliRunner()


def master(base: str) -> httpx.Client:
    token = httpx.post(
        f"{base}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
        timeout=30,
    ).json()["access_token"]
    return httpx.Client(
        base_url=f"{base}/admin/realms/{REALM}", headers={"Authorization": f"Bearer {token}"}, timeout=60
    )


def bootstrap(base: str, tmp_path: Path, *extra: str):
    return runner.invoke(
        app,
        [
            "keycloak", "bootstrap", str(PLATFORM_YAML), "-u", base, "-r", REALM,
            "--admin-user", "admin", "--admin-password", "admin",
            "--secrets-file", str(tmp_path / "secrets.yaml"), *extra,
        ],
    )


def platform_level(base: str) -> dict:
    export = master(base).post("/partial-export?exportClients=false&exportGroupsAndRoles=true").json()
    declared = yaml.safe_load(PLATFORM_YAML.read_text())
    values = {}
    for key in [*declared["realm_settings"], "bruteForceProtected"]:
        value = export.get(key)
        values[key] = sorted(value) if key == "supportedLocales" and value else value
    values["role_groups"] = {
        g["path"]: sorted(g.get("realmRoles") or []) for g in export.get("groups", [])
        if g["path"] in {rg["path"] for rg in declared["role_groups"]}
    }
    values["realm_roles"] = sorted(
        r["name"] for r in export.get("roles", {}).get("realm", [])
        if r["name"] in {rg["realm_role"] for rg in declared["role_groups"]}
    )
    return values


@pytest.fixture(scope="module")
def converged(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("parity")
    # A first run on the imported realm; on the empty one it creates the realm.
    results = {}
    for name, url in (("imported", IMPORTED), ("empty", EMPTY)):
        (tmp / name).mkdir()
        results[name] = bootstrap(url, tmp / name)
        assert results[name].exit_code == 0, f"{name}: {results[name].output}"
    assert "realm created" in results["empty"].output
    return tmp


def test_a_realm_bootstrap_created_equals_the_imported_one_at_platform_level(converged):
    imported, created = platform_level(IMPORTED), platform_level(EMPTY)

    differences = {k: (imported[k], created.get(k)) for k in imported if imported[k] != created.get(k)}
    assert differences == {}


def test_both_match_the_declaration(converged):
    declared = yaml.safe_load(PLATFORM_YAML.read_text())
    for base in (IMPORTED, EMPTY):
        values = platform_level(base)
        for key, value in declared["realm_settings"].items():
            expected = sorted(value) if key == "supportedLocales" else value
            assert values[key] == expected, (base, key)
        assert values["role_groups"] == {rg["path"]: [rg["realm_role"]] for rg in declared["role_groups"]}


@pytest.mark.parametrize("which", ["imported", "empty"])
def test_a_second_run_finds_nothing_to_change(converged, which):
    base = IMPORTED if which == "imported" else EMPTY
    (converged / f"{which}-check").mkdir()
    result = bootstrap(base, converged / f"{which}-check", "--check")
    assert result.exit_code == 0, result.output


def account_console(base: str) -> tuple[httpx.Client, str]:
    kc = master(base)
    client = kc.get("/clients", params={"clientId": "account-console"}).json()[0]
    return kc, client["id"]


@pytest.mark.parametrize("which", ["imported", "empty"])
def test_the_account_console_has_keycloaks_default_scopes(converged, which):
    kc, uuid = account_console(IMPORTED if which == "imported" else EMPTY)
    names = {s["name"] for s in kc.get(f"/clients/{uuid}/default-client-scopes").json()}
    assert set(ACCOUNT_CONSOLE_DEFAULT_SCOPES) <= names


def test_the_account_console_token_carries_the_account_roles(converged):
    """What the Account API checks. Without `roles` in the defaults it is absent: 403."""
    kc, uuid = account_console(IMPORTED)
    # A person, not a service account: default roles are what grant `manage-account`.
    users = kc.get("/users", params={"username": "parity-console", "exact": "true"}).json()
    if not users:
        kc.post("/users", json={"username": "parity-console", "enabled": True, "email": "parity@example.org",
                                "firstName": "Parity", "lastName": "Console"}).raise_for_status()
        users = kc.get("/users", params={"username": "parity-console", "exact": "true"}).json()
    token = kc.get(
        f"/clients/{uuid}/evaluate-scopes/generate-example-access-token",
        params={"scope": "openid", "userId": users[0]["id"]},
    ).json()
    assert "manage-account" in token["resource_access"]["account"]["roles"]
