"""User lookups encode the value they search for.

A plus-addressed email (`someone+tag@example.test`) was sent unencoded, so Keycloak
read the `+` as a space and matched nobody. The provisioning service then created the
account, failed to read it back ("Failed to retrieve user after creation") and answered
500, leaving the account behind. Found on the celine-dev stack, 2026-09-14.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from celine.policies.cli.keycloak.client import KeycloakAdminClient
from celine.policies.cli.keycloak.settings import KeycloakSettings

ADDRESS = "invite-e2e+1@example.test"


def _client(seen: list[httpx.Request]) -> KeycloakAdminClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        query = parse_qs(urlsplit(str(request.url)).query)
        found = [{"id": "u-1", "username": ADDRESS, "email": ADDRESS}]
        wanted = (query.get("username") or query.get("email") or [""])[0]
        return httpx.Response(200, json=found if wanted == ADDRESS else [])

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


@pytest.mark.parametrize("lookup", ["get_user_by_username", "get_user_by_email"])
async def test_a_plus_addressed_value_is_found(lookup: str) -> None:
    seen: list[httpx.Request] = []
    client = _client(seen)

    user = await getattr(client, lookup)(ADDRESS)

    assert user is not None and user["id"] == "u-1"
    assert "%2B" in seen[0].url.raw_path.decode()
