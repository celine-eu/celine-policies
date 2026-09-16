"""Lookups encode the value they search for.

A plus-addressed email (`someone+tag@example.test`) was sent unencoded, so Keycloak
read the `+` as a space and matched nobody. The provisioning service then created the
account, failed to read it back ("Failed to retrieve user after creation") and answered
500, leaving the account behind. Found on the celine-dev stack, 2026-09-14.

The client, group and policy lookups take platform-controlled names, and get the same
treatment so that no query value is ever interpolated into a path (issue #7).
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from celine.policies.cli.keycloak.client import KeycloakAdminClient
from celine.policies.cli.keycloak.settings import KeycloakSettings

VALUE = "invite-e2e+1@example.test"
FOUND = {
    "id": "x-1",
    "username": VALUE,
    "email": VALUE,
    "clientId": VALUE,
    "name": VALUE,
    "path": f"/{VALUE}",
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


LOOKUPS = {
    "get_user_by_username": ("username", lambda c: c.get_user_by_username(VALUE)),
    "get_user_by_email": ("email", lambda c: c.get_user_by_email(VALUE)),
    "get_client_by_client_id": ("clientId", lambda c: c.get_client_by_client_id(VALUE)),
    "get_group_by_path": ("search", lambda c: c.get_group_by_path(f"/{VALUE}")),
    "find_admin_policy_by_name": (
        "name",
        lambda c: c.find_admin_policy_by_name("ap-1", VALUE),
    ),
}


@pytest.mark.parametrize("lookup", sorted(LOOKUPS))
async def test_a_plus_in_the_value_is_found(lookup: str) -> None:
    key, call = LOOKUPS[lookup]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        query = parse_qs(urlsplit(str(request.url)).query)
        wanted = (query.get(key) or [""])[0]
        return httpx.Response(200, json=[FOUND] if wanted == VALUE else [])

    result = await call(_client(handler))

    assert result is not None and result["id"] == "x-1"
    assert "%2B" in seen[0].url.raw_path.decode()


async def test_organization_members_are_read_past_the_first_page() -> None:
    """Keycloak pages the members listing; a caller must see every member (#8)."""
    everyone = [{"id": f"u-{i}"} for i in range(7)]
    seen: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/organizations/org-1/members")
        query = parse_qs(request.url.query.decode())
        seen.append(query)
        first, size = int(query["first"][0]), int(query["max"][0])
        return httpx.Response(200, json=everyone[first : first + size])

    members = await _client(handler).get_organization_members("org-1", page_size=3)

    assert members == everyone
    assert [q["first"] for q in seen] == [["0"], ["3"], ["6"]]


async def test_an_exact_page_asks_once_more_and_stops_on_empty() -> None:
    everyone = [{"id": f"u-{i}"} for i in range(4)]
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        query = parse_qs(request.url.query.decode())
        first, size = int(query["first"][0]), int(query["max"][0])
        return httpx.Response(200, json=everyone[first : first + size])

    members = await _client(handler).get_organization_members("org-1", page_size=2)

    assert members == everyone
    assert calls == 3
