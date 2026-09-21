"""`keycloak sync --additive` against a real Keycloak: a scope granted by hand survives.

Test T14 of plan a-sync-can-be-told-to-only-add. Skipped unless a Keycloak is named:

    CELINE_SYNC_KEYCLOAK_URL   any Keycloak accepting the master admin `admin`/`admin`
                               (falls back to CELINE_PARITY_EMPTY_URL, which CI starts)

It creates and deletes a realm of its own, `additive-sync-test`, and touches nothing else,
so it can share a Keycloak with the parity test. The stock `quay.io/keycloak/keycloak` image
is enough; no theme is needed.

The sequence, and why it is in this order: a plain sync creates the declared client; a
scope is then made and assigned to it by hand, as an operator would. `sync --additive` must
leave that assignment in place and name it as held back, twice in a row, and leave the
`groups` claim scope on the realm default list where it was put back by hand. Only then does a
plain `sync` run, and it must remove both — which is what proves the additive run
was really handed a removal and declined it, rather than planning nothing.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from celine.policies.cli.main import app

BASE = os.environ.get("CELINE_SYNC_KEYCLOAK_URL") or os.environ.get("CELINE_PARITY_EMPTY_URL")
REALM = "additive-sync-test"

pytestmark = pytest.mark.skipif(
    not BASE, reason="needs a Keycloak: CELINE_SYNC_KEYCLOAK_URL (or CELINE_PARITY_EMPTY_URL)"
)

runner = CliRunner()

DECLARATION = f"""\
realm: {REALM}
scopes:
  - name: alpha.read
    description: read alpha
clients:
  - client_id: svc-alpha
    name: svc-alpha
    secret: additive-test-secret
    scopes_prefix: alpha
    default_scopes: [alpha.read]
"""


def master() -> httpx.Client:
    token = httpx.post(
        f"{BASE}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
        timeout=30,
    ).json()["access_token"]
    return httpx.Client(base_url=f"{BASE}/admin/realms", headers={"Authorization": f"Bearer {token}"}, timeout=60)


def sync(tmp_path: Path, *extra: str):
    return runner.invoke(
        app,
        [
            "keycloak", "sync", str(tmp_path / "clients.yaml"), "-u", BASE, "-r", REALM,
            "--admin-user", "admin", "--admin-password", "admin",
            "--secrets-file", str(tmp_path / "secrets.yaml"), *extra,
        ],
    )


def default_scopes_of(kc: httpx.Client, client_id: str) -> set[str]:
    uuid = kc.get(f"/{REALM}/clients", params={"clientId": client_id}).json()[0]["id"]
    return {s["name"] for s in kc.get(f"/{REALM}/clients/{uuid}/default-client-scopes").json()}


def realm_default_scopes(kc: httpx.Client) -> set[str]:
    return {s["name"] for s in kc.get(f"/{REALM}/default-default-client-scopes").json()}


@pytest.fixture
def realm(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ENV", "dev")
    (tmp_path / "clients.yaml").write_text(DECLARATION)
    kc = master()
    kc.delete(f"/{REALM}")
    kc.post("", json={"realm": REALM, "enabled": True}).raise_for_status()
    yield kc
    kc.delete(f"/{REALM}")


def test_t14_a_hand_made_assignment_survives_additive_and_not_a_full_sync(realm, tmp_path):
    kc = realm

    first = sync(tmp_path)
    assert first.exit_code == 0, first.output

    # An operator grants a scope no file declares.
    kc.post(f"/{REALM}/client-scopes", json={"name": "hand.made", "protocol": "openid-connect"}).raise_for_status()
    scope_id = next(s["id"] for s in kc.get(f"/{REALM}/client-scopes").json() if s["name"] == "hand.made")
    uuid = kc.get(f"/{REALM}/clients", params={"clientId": "svc-alpha"}).json()[0]["id"]
    kc.put(f"/{REALM}/clients/{uuid}/default-client-scopes/{scope_id}").raise_for_status()
    assert "hand.made" in default_scopes_of(kc, "svc-alpha")

    # And puts a realm claim scope back on the realm's default list, which the
    # claim-scope step of every full sync takes it off (T11, live).
    groups_id = next(s["id"] for s in kc.get(f"/{REALM}/client-scopes").json() if s["name"] == "groups")
    kc.put(f"/{REALM}/default-default-client-scopes/{groups_id}").raise_for_status()

    for _ in range(2):
        additive = sync(tmp_path, "--additive")
        assert additive.exit_code == 0, additive.output
        assert "  = svc-alpha <- hand.made (default)" in additive.output
        assert "Scope assignments to remove" not in additive.output
        assert "hand.made" in default_scopes_of(kc, "svc-alpha")
        assert "  = groups (realm default)" in additive.output
        assert "groups" in realm_default_scopes(kc)

    dry = sync(tmp_path, "--additive", "--dry-run")
    assert dry.exit_code == 0, dry.output
    assert "  = svc-alpha <- hand.made (default)" in dry.output
    assert "  = groups (realm default)" in dry.output

    refused = sync(tmp_path, "--additive", "--prune")
    assert refused.exit_code == 2

    full = sync(tmp_path)
    assert full.exit_code == 0, full.output
    assert "  - svc-alpha <- hand.made (default)" in full.output
    assert "hand.made" not in default_scopes_of(kc, "svc-alpha")
    assert "groups" not in realm_default_scopes(kc)
