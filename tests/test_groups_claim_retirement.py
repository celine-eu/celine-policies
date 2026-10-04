"""The realm `groups` claim is retired: a full `sync` leaves no mapper writing it (REQ-0013).

The starting states are the ones measured on the local realm (2026-10-03): the `groups` client
scope's group-membership mapper (`full.path: true`, `/admins`), a client-level one on
`oauth2_proxy` (`full.path: false`, `admins`), and `microprofile-jwt`'s realm-role mapper
writing roles into `groups`. Organization groups reach a token through the `organization`
scope's own mapper, which is never touched. Keycloak's HTTP layer is faked; the run against a
real 26.7.3 is `tests/integration/test_platform_admin_role.py`.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from celine.policies.cli.keycloak.client import REALM_CLAIM_SCOPES, KeycloakAdminClient
from celine.policies.cli.keycloak.settings import KeycloakSettings

GROUPS_SCOPE_MAPPER = {
    "id": "m-groups", "name": "groups", "protocolMapper": "oidc-group-membership-mapper",
    "config": {"claim.name": "groups", "full.path": "true"},
}
PROXY_MAPPER = {
    "id": "m-proxy", "name": "groups", "protocolMapper": "oidc-group-membership-mapper",
    "config": {"claim.name": "groups", "full.path": "false"},
}
MICROPROFILE_MAPPER = {
    "id": "m-mp", "name": "groups", "protocolMapper": "oidc-usermodel-realm-role-mapper",
    "config": {"claim.name": "groups", "multivalued": "true"},
}
UPN_MAPPER = {
    "id": "m-upn", "name": "upn", "protocolMapper": "oidc-usermodel-attribute-mapper",
    "config": {"claim.name": "upn"},
}
ORG_MAPPERS = [
    {"id": "m-org", "name": "organization", "protocolMapper": "oidc-organization-membership-mapper",
     "config": {"claim.name": "organization"}},
    {"id": "m-orggroups", "name": "organization group membership",
     "protocolMapper": "oidc-organization-group-membership-mapper", "config": {}},
]
AUDIENCE = {"id": "m-aud", "name": "aud-svc-x", "protocolMapper": "oidc-audience-mapper", "config": {}}


def realm_client(*, old: bool) -> KeycloakAdminClient:
    scopes = [
        {"id": "s-org", "name": "organization", "protocol": "openid-connect"},
        {"id": "s-mp", "name": "microprofile-jwt", "protocol": "openid-connect"},
        {"id": "s-saml", "name": "role_list", "protocol": "saml"},
    ]
    mappers = {"s-org": ORG_MAPPERS, "s-mp": [UPN_MAPPER] + ([MICROPROFILE_MAPPER] if old else [])}
    if old:
        scopes.append({"id": "s-groups", "name": "groups", "protocol": "openid-connect"})
        mappers["s-groups"] = [GROUPS_SCOPE_MAPPER]
    clients = [
        {"id": "c-proxy", "clientId": "oauth2_proxy", "protocolMappers": [AUDIENCE] + ([PROXY_MAPPER] if old else [])},
        {"id": "c-svc", "clientId": "svc-x", "protocolMappers": [AUDIENCE]},
    ]
    kc = KeycloakAdminClient(KeycloakSettings(env="dev"))
    kc.list_client_scopes = AsyncMock(return_value=scopes)
    kc.get_scope_protocol_mappers = AsyncMock(side_effect=lambda sid: mappers.get(sid, []))
    kc.list_clients = AsyncMock(return_value=clients)
    kc._delete = AsyncMock()
    kc.delete_protocol_mapper = AsyncMock()
    kc.delete_client_scope = AsyncMock()
    return kc


class TestTheGroupsClaimIsRetired:
    @pytest.mark.asyncio
    async def test_every_mapper_writing_it_and_the_scope_go(self):
        """@verifies REQ-0013"""
        kc = realm_client(old=True)

        removed = await kc.retire_groups_claim()

        kc._delete.assert_awaited_once_with("/client-scopes/s-mp/protocol-mappers/models/m-mp")
        kc.delete_protocol_mapper.assert_awaited_once_with("c-proxy", "m-proxy")
        kc.delete_client_scope.assert_awaited_once_with("s-groups")
        assert removed == [
            "client scope microprofile-jwt: mapper groups (oidc-usermodel-realm-role-mapper)",
            "client scope groups",
            "client oauth2_proxy: mapper groups (oidc-group-membership-mapper)",
        ]

    @pytest.mark.asyncio
    async def test_a_converged_realm_is_left_alone(self):
        """@verifies REQ-0013"""
        kc = realm_client(old=False)

        assert await kc.retire_groups_claim() == []

        kc._delete.assert_not_awaited()
        kc.delete_protocol_mapper.assert_not_awaited()
        kc.delete_client_scope.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_without_remove_it_only_reports(self):
        """`sync --additive` and a dry run. @verifies REQ-0013"""
        kc = realm_client(old=True)

        assert len(await kc.retire_groups_claim(remove=False)) == 3

        kc._delete.assert_not_awaited()
        kc.delete_protocol_mapper.assert_not_awaited()
        kc.delete_client_scope.assert_not_awaited()

    @pytest.mark.parametrize(
        ("mapper", "writes"),
        [
            (GROUPS_SCOPE_MAPPER, True),
            (PROXY_MAPPER, True),
            (MICROPROFILE_MAPPER, True),
            # A group-membership mapper under another claim name still carries realm groups.
            ({"protocolMapper": "oidc-group-membership-mapper", "config": {"claim.name": "memberOf"}}, True),
            (ORG_MAPPERS[0], False),
            (ORG_MAPPERS[1], False),
            (UPN_MAPPER, False),
            (AUDIENCE, False),
        ],
    )
    def test_which_mappers_count(self, mapper, writes):
        """@verifies REQ-0013"""
        assert KeycloakAdminClient.writes_groups_claim(mapper) is writes

    def test_groups_is_no_longer_a_claim_scope_sync_provisions(self):
        """@verifies REQ-0013"""
        assert REALM_CLAIM_SCOPES == ("organization", "dataspace")


class TestASignInClientCarriesRealmRoles:
    def test_a_browser_client_without_roles_is_refused(self):
        """@verifies REQ-0013"""
        from celine.policies.cli.keycloak.models import BrowserLogin, ClientConfig

        with pytest.raises(ValueError, match="roles"):
            ClientConfig(client_id="web", browser=BrowserLogin(redirect_uris=["http://x/*"]))
        ClientConfig(client_id="web", default_scopes=["roles"], browser=BrowserLogin(redirect_uris=["http://x/*"]))

    def test_a_service_client_needs_no_roles(self):
        from celine.policies.cli.keycloak.models import ClientConfig

        ClientConfig(client_id="svc-x", default_scopes=["x.read"])

    def test_every_shipped_browser_client_holds_roles(self):
        """@verifies REQ-0013"""
        from pathlib import Path

        from celine.policies.cli.keycloak.models import KeycloakConfig

        root = Path(__file__).resolve().parents[1]
        config = KeycloakConfig.from_yaml(root / "clients.yaml")
        browsers = [c for c in config.clients if c.browser is not None]
        assert browsers and all("roles" in c.default_scopes for c in browsers)
