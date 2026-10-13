"""Where a real Keycloak lets a client sign out to, by its `post.logout.redirect.uris`.

`BrowserLogin.post_logout_redirect_uris` writes this attribute; these pin what each value
means on the server the realm runs (26.7.3). Runs against the parity Keycloak
(`CELINE_PARITY_IMPORTED_URL`, master admin `admin`/`admin`) and is skipped without it.

A throwaway client is created with one redirect URI, and the logout endpoint is asked to
return to an address: an allowed address is answered without a 400 (the logout
confirmation page, as there is no session), a refused one with Keycloak's 400.

Seen on staging 2026-10-13: an explicit list set by hand decided the sign-out, whatever
the redirect URIs said.
"""

from __future__ import annotations

import os
import uuid

import httpx
import pytest

IMPORTED = os.environ.get("CELINE_PARITY_IMPORTED_URL")
REALM = "celine"
ATTRIBUTE = "post.logout.redirect.uris"

pytestmark = pytest.mark.skipif(not IMPORTED, reason="needs a Keycloak: CELINE_PARITY_IMPORTED_URL")


def admin() -> httpx.Client:
    token = httpx.post(
        f"{IMPORTED}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
        timeout=30,
    ).json()["access_token"]
    return httpx.Client(base_url=f"{IMPORTED}/admin", headers={"Authorization": f"Bearer {token}"}, timeout=60)


@pytest.fixture
def client_with():
    """Create a client whose attribute is the given value (None: unset), and remove it after."""
    made: list[str] = []
    kc = admin()

    def make(value: str | None) -> str:
        client_id = f"test-logout-{uuid.uuid4().hex[:8]}"
        attributes = {} if value is None else {ATTRIBUTE: value}
        kc.post(f"/realms/{REALM}/clients", json={
            "clientId": client_id, "publicClient": False, "secret": "s",
            "standardFlowEnabled": True, "redirectUris": ["http://app.example.org/*"],
            "attributes": attributes,
        }).raise_for_status()
        made.append(kc.get(f"/realms/{REALM}/clients", params={"clientId": client_id}).json()[0]["id"])
        return client_id

    yield make
    for uuid_ in made:
        kc.delete(f"/realms/{REALM}/clients/{uuid_}")
    kc.close()


def signs_out_to(client_id: str, address: str) -> bool:
    response = httpx.get(
        f"{IMPORTED}/realms/{REALM}/protocol/openid-connect/logout",
        params={"client_id": client_id, "post_logout_redirect_uri": address},
        timeout=30,
    )
    assert response.status_code in (200, 302, 400), response.status_code
    return response.status_code != 400


APP = "http://app.example.org/signed-out"
OTHER = "http://other.example.org/signed-out"


@pytest.mark.parametrize(
    ("value", "app", "other"),
    [
        (None, True, False),  # unset falls back to the redirect URIs, like "+"
        ("+", True, False),
        (OTHER, False, True),
        (f"+##{OTHER}", True, True),
        (f"{OTHER}##+", True, True),
    ],
)
def test_the_attribute_decides_where_a_client_signs_out_to(client_with, value, app, other):
    client_id = client_with(value)
    assert signs_out_to(client_id, APP) is app
    assert signs_out_to(client_id, OTHER) is other


def test_the_value_is_read_back_as_written(client_with):
    """`sync` compares what it reads with what it writes, so a rewrite must be stable."""
    value = f"+##{OTHER}"
    client_id = client_with(value)
    with admin() as kc:
        rep = kc.get(f"/realms/{REALM}/clients", params={"clientId": client_id}).json()[0]
    assert rep["attributes"][ATTRIBUTE] == value
