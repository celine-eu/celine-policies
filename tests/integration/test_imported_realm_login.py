"""The imported realm's login pages, rendered by a real Keycloak with the `rec` theme.

Runs against the same Keycloak as the parity test (`CELINE_PARITY_IMPORTED_URL`, master admin
`admin`/`admin`, this repository's `keycloak` image) and is skipped without it.

- the account theme the import names exists on the server;
- the login page carries the import map Keycloak's WebAuthn scripts need;
- with passkeys enabled, it offers one: the button and the `username webauthn` autofill.
  Passkeys are turned on for the test and restored afterwards.

The WebAuthn ceremony itself needs a browser; it was run with a virtual authenticator in the
plan's work directory (participants-may-choose-a-passkey-or-a-one-time-code).
"""

from __future__ import annotations

import os
import re

import httpx
import pytest

IMPORTED = os.environ.get("CELINE_PARITY_IMPORTED_URL")
REALM = "celine"

pytestmark = pytest.mark.skipif(not IMPORTED, reason="needs a Keycloak: CELINE_PARITY_IMPORTED_URL")


def admin() -> httpx.Client:
    token = httpx.post(
        f"{IMPORTED}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
        timeout=30,
    ).json()["access_token"]
    return httpx.Client(base_url=f"{IMPORTED}/admin", headers={"Authorization": f"Bearer {token}"}, timeout=60)


def login_page() -> str:
    # Any client with a browser login will do; account-console is always there.
    response = httpx.get(
        f"{IMPORTED}/realms/{REALM}/protocol/openid-connect/auth",
        params={"client_id": "account-console", "response_type": "code", "scope": "openid",
                "redirect_uri": f"{IMPORTED}/realms/{REALM}/account/",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"},
        timeout=30,
    )
    assert response.status_code == 200
    return response.text


@pytest.fixture
def passkeys_on():
    with admin() as kc:
        realm = kc.get(f"/realms/{REALM}").json()
        before = realm.get("webAuthnPolicyPasswordlessPasskeysEnabled", False)
        # Sent alone, the flag is dropped without an error: it needs the policy block with it.
        body = {"webAuthnPolicyPasswordlessRpEntityName": realm["webAuthnPolicyPasswordlessRpEntityName"]}
        kc.put(f"/realms/{REALM}", json={**body, "webAuthnPolicyPasswordlessPasskeysEnabled": True}).raise_for_status()
        assert kc.get(f"/realms/{REALM}").json()["webAuthnPolicyPasswordlessPasskeysEnabled"] is True
        yield
        kc.put(f"/realms/{REALM}", json={**body, "webAuthnPolicyPasswordlessPasskeysEnabled": before}).raise_for_status()


def test_the_account_theme_exists_on_the_server():
    with admin() as kc:
        themes = {t["name"] for t in kc.get("/serverinfo").json()["themes"]["account"]}
        assert kc.get(f"/realms/{REALM}").json()["accountTheme"] in themes


def test_the_login_page_maps_rfc4648():
    page = login_page()
    assert '<script type="importmap">' in page
    assert "/vendor/rfc4648/rfc4648.js" in page


def test_with_passkeys_on_the_login_page_offers_one(passkeys_on):
    page = login_page()
    assert 'id="authenticateWebAuthnButton"' in page
    assert re.search(r'id="username"[^>]*autocomplete="username webauthn"', page)
    assert "passkeysConditionalAuth.js" in page
