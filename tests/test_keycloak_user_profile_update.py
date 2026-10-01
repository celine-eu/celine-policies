"""`update_user_profile` writes names and address and never the username.

The provisioning `PATCH /participants/{community}/{key}` rests on this: the
username is the stable identity the registry and the identity registry key on,
so the representation put back carries it exactly as read, together with every
attribute the change did not name.
"""

from __future__ import annotations

import json

import httpx
import pytest

from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakConflictError,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings

ACCOUNT = {
    "id": "u-1",
    "username": "ex-00001",
    "email": "old@example.org",
    "emailVerified": True,
    "firstName": "One",
    "lastName": "Member",
    "enabled": True,
    "attributes": {"locale": ["it"]},
}


def _client(handler) -> KeycloakAdminClient:
    client = KeycloakAdminClient(
        KeycloakSettings(
            base_url="http://kc.test",
            realm="celine",
            admin_user="admin",
            admin_password="admin",
        )
    )
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def no_auth() -> dict[str, str]:
        return {}

    client._headers = no_auth  # type: ignore[method-assign]
    return client


def _recording(put_status: int = 204):
    puts: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=ACCOUNT)
        puts.append(json.loads(request.content))
        return httpx.Response(put_status, text="User exists with same email")

    return handler, puts


async def test_an_address_change_puts_back_the_username_and_every_other_field() -> None:
    handler, puts = _recording()

    await _client(handler).update_user_profile(
        "u-1", email="new@example.org", email_verified=False
    )

    assert puts == [
        {**ACCOUNT, "email": "new@example.org", "emailVerified": False}
    ]
    assert puts[0]["username"] == "ex-00001"


async def test_a_name_change_leaves_the_address_and_its_verification() -> None:
    handler, puts = _recording()

    await _client(handler).update_user_profile("u-1", first_name="Anna")

    assert puts == [{**ACCOUNT, "firstName": "Anna"}]


async def test_a_realm_refusing_a_duplicate_address_surfaces_as_a_conflict() -> None:
    handler, _ = _recording(put_status=409)

    with pytest.raises(KeycloakConflictError):
        await _client(handler).update_user_profile("u-1", email="taken@example.org")


async def test_the_address_confirmation_is_keycloaks_verify_email_not_an_actions_email() -> None:
    """`send-verify-email` renders the theme's `email-verification` template under
    "confirm your email address"; `execute-actions-email` would carry the
    invitation's fixed subject whatever its actions."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    await _client(handler).send_verify_email(
        "u-1",
        lifespan=604800,
        client_id="oauth2_proxy",
        redirect_uri="http://webapp.celine.localhost/",
    )

    (request,) = seen
    assert request.method == "PUT"
    assert request.url.path == "/admin/realms/celine/users/u-1/send-verify-email"
    assert "execute-actions-email" not in str(request.url)
    assert dict(request.url.params) == {
        "lifespan": "604800",
        "redirect_uri": "http://webapp.celine.localhost/",
        "client_id": "oauth2_proxy",
    }
